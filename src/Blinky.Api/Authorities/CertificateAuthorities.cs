using System.Text.Json;
using Blinky.Api.Persistence;
using Blinky.Domain;
using Blinky.Domain.Entities;
using Blinky.Pki;
using Blinky.Pki.Adcs;
using Blinky.Pki.BuiltIn;
using NHibernate.Linq;

namespace Blinky.Api.Authorities;

/// <summary>
/// The certificate authorities this deployment issues from, built from
/// <see cref="CaInstance"/> rows rather than from <c>.env</c> (0108).
/// </summary>
/// <remarks>
/// <para>
/// One CA per process, chosen at start by <c>CA_BACKEND</c>, was a setting only
/// somebody with a shell could change. The first issuance through MS-CONN01 sat on
/// an empty <c>Connector:CaConfig</c> for exactly that reason. A row is changed from
/// the console, and the next request gets a CA built from the new row.
/// </para>
/// <para>
/// Built lazily and kept until a row changes. A Microsoft CA behind a connector is
/// not touched at build time - <see cref="AdcsInstance.Create"/> checks only what is
/// local - so building on demand costs nothing and an API still starts while the CA
/// server is being patched.
/// </para>
/// <para>
/// A replaced authority is not disposed. A request already inside it may be waiting
/// on the CA; disposing would fail a submission that was going to succeed, and the
/// cost of not disposing is one idle HttpClient until the process restarts.
/// </para>
/// </remarks>
public sealed class CertificateAuthorities(
    Database database,
    IConfiguration configuration,
    ConnectorQueue queue,
    ILogger<CertificateAuthorities> logger)
{
    internal static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    private readonly Lock gate = new();
    private readonly Dictionary<Guid, ICertificateAuthority> built = [];

    /// <summary>
    /// The CA used where no profile chooses one: the status page, /pki, revocation of a
    /// credential that predates 0108. The oldest enabled row.
    /// </summary>
    public ICertificateAuthority Default => For(DefaultId());

    /// <summary>The first enabled Microsoft CA, for the directory reads its connector makes (0104).</summary>
    public AdcsCertificateAuthority? Adcs
    {
        get
        {
            using var session = database.OpenSession();
            var id = session.Query<CaInstance>()
                .Where(c => c.IsEnabled && c.Backend == CaBackend.Adcs)
                .OrderBy(c => c.CreatedAt)
                .Select(c => (Guid?)c.Id)
                .FirstOrDefault();

            return id is { } found ? For(found) as AdcsCertificateAuthority : null;
        }
    }

    public ICertificateAuthority For(Guid id)
    {
        lock (gate)
        {
            if (built.TryGetValue(id, out var known))
            {
                return known;
            }
        }

        using var session = database.OpenSession();
        var row = session.Get<CaInstance>(id)
                  ?? throw new CertificateAuthorityException($"There is no CA with id {id}.");

        if (!row.IsEnabled)
        {
            throw new CertificateAuthorityException(
                $"The CA {row.Name} is disabled. Enable it in the console, or point the profile at another.");
        }

        var profiles = session.Query<CertificateProfile>()
            .Where(p => p.CaInstance.Id == id && p.IsEnabled)
            .ToList();

        var authority = Build(row, profiles, configuration, queue);

        lock (gate)
        {
            built[id] = authority;
        }

        logger.LogInformation("Built the CA {Name} ({Backend}) from its row", row.Name, row.Backend);
        return authority;
    }

    /// <summary>A row or a profile changed: every CA is built again at its next use.</summary>
    public void Forget()
    {
        lock (gate)
        {
            built.Clear();
        }
    }

    private Guid DefaultId()
    {
        using var session = database.OpenSession();

        return session.Query<CaInstance>()
                   .Where(c => c.IsEnabled)
                   .OrderBy(c => c.CreatedAt)
                   .Select(c => (Guid?)c.Id)
                   .FirstOrDefault()
               ?? throw new CertificateAuthorityException(
                   "No certificate authority is configured. Add one in the console: Administracja / CA i profile.");
    }

    /// <summary>One authority from its row and the profiles that name it.</summary>
    /// <remarks>
    /// The ADCS template map is assembled from the profiles rather than stored on the
    /// row: the template is a property of what is issued, and keeping a second copy
    /// on the CA is how the two would come to disagree.
    /// </remarks>
    public static ICertificateAuthority Build(CaInstance row, IReadOnlyCollection<CertificateProfile> profiles,
        IConfiguration configuration, ConnectorQueue queue)
    {
        if (row.Backend == CaBackend.Adcs)
        {
            var options = AdcsSettingsOf(row);
            options.Name = row.Name;
            options.Templates = profiles
                .Where(p => !string.IsNullOrWhiteSpace(p.AdcsTemplateName))
                .ToDictionary(p => p.Name, p => p.AdcsTemplateName!, StringComparer.Ordinal);

            return AdcsInstance.Create(options, issues: true, queue);
        }

        var builtIn = BuiltInSettingsOf(row);

        // The key's password and the file-key switch stay in .env: they open the CA's
        // own key, and a database holding the password to the key that signs every
        // credential would make a backup of the database a copy of the CA.
        return BuiltInCaFactory.LoadFromDirectory(
            builtIn.Directory ?? configuration["Blinky:Ca:Directory"] ?? "/etc/blinky/ca",
            configuration["Blinky:Ca:Password"],
            configuration.GetValue("Blinky:Ca:AllowFileKeys", false),
            TimeSpan.FromHours(configuration.GetValue("Blinky:Ca:CrlValidityHours", 8)),
            CaPublication.FromBaseUrl(configuration["Blinky:Ca:PublicUrl"], configuration["Blinky:Ca:OcspUrl"]));
    }

    public static AdcsInstanceOptions AdcsSettingsOf(CaInstance row) =>
        JsonSerializer.Deserialize<AdcsInstanceOptions>(row.Configuration, Json) ?? new AdcsInstanceOptions();

    public static BuiltInSettings BuiltInSettingsOf(CaInstance row) =>
        JsonSerializer.Deserialize<BuiltInSettings>(row.Configuration, Json) ?? new BuiltInSettings(null);

    /// <summary>
    /// What a row's configuration may hold. Secrets typed as values are dropped, not
    /// stored: the connector's client certificate and a file-held agent key are named
    /// by a password file, which is what the existing options recommend anyway.
    /// </summary>
    public static string Serialise(AdcsInstanceOptions options)
    {
        options.Templates = new Dictionary<string, string>(StringComparer.Ordinal);
        options.Connector.ClientCertificatePassword = null;
        options.EnrolmentAgent.Password = null;

        return JsonSerializer.Serialize(options, Json);
    }
}

/// <summary>Where the built-in CA's files are, when not the deployment's default.</summary>
public sealed record BuiltInSettings(string? Directory);

/// <summary>
/// The CA everything that does not choose one is given: the default instance, behind
/// the interface the rest of the API was written against.
/// </summary>
/// <remarks>
/// Fifteen places take an <see cref="ICertificateAuthority"/> from the container and
/// would otherwise each have had to learn about rows. A place that needs the concrete
/// backend - the status page, the registration checks - asks
/// <see cref="CertificateAuthorities.Default"/> instead, because a proxy is never one.
/// </remarks>
public sealed class DefaultCertificateAuthority(CertificateAuthorities authorities) : ICertificateAuthority
{
    public string Name => authorities.Default.Name;

    public Task<CaCapabilities> DescribeAsync(CancellationToken ct = default) =>
        authorities.Default.DescribeAsync(ct);

    public Task<IssuedCertificate> IssueAsync(CertificateRequestContext context, CancellationToken ct = default) =>
        authorities.Default.IssueAsync(context, ct);

    public Task RevokeAsync(RevocationRequest request, CancellationToken ct = default) =>
        authorities.Default.RevokeAsync(request, ct);

    public Task<CrlDocument?> GetCrlAsync(CancellationToken ct = default) =>
        authorities.Default.GetCrlAsync(ct);
}
