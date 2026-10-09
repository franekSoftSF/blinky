using System.Text.Json;
using System.Text.RegularExpressions;
using Blinky.Api.Persistence;
using Blinky.Domain;
using Blinky.Domain.Entities;
using Blinky.Piv;
using Blinky.Pki;
using Blinky.Pki.Adcs;
using NHibernate.Linq;

namespace Blinky.Api.Authorities;

/// <summary>
/// The console's CRUD over certificate authorities and certificate profiles (0108).
/// </summary>
/// <remarks>
/// <para>
/// Configuration, so it gets the full set - list, read, create, edit, delete - in the
/// change that made it a row. Two refusals are the exception the repository's rule
/// allows for history: a CA or a profile that an issued credential points at is not
/// deleted, because the credential row outlives it and has to keep saying where it
/// came from. Disable it instead.
/// </para>
/// <para>
/// Every write rebuilds the CAs at their next use, so a corrected template or CA name
/// takes effect on the next enrolment without a restart.
/// </para>
/// </remarks>
public sealed partial class CaAdministration(
    Database database,
    CertificateAuthorities authorities,
    IConfiguration configuration,
    ConnectorQueue queue)
{
    /// <summary>Algorithms the agent can generate on a YubiKey and a CA can certify.</summary>
    public static readonly IReadOnlyList<string> KeyAlgorithms =
        [nameof(PivAlgorithm.Rsa2048), nameof(PivAlgorithm.Rsa3072), nameof(PivAlgorithm.Rsa4096),
         nameof(PivAlgorithm.EccP256), nameof(PivAlgorithm.EccP384)];

    public static readonly IReadOnlyList<string> Slots = ["9A", "9C", "9D", "9E"];

    public static readonly IReadOnlyList<string> PinPolicies =
        Enum.GetNames<PinPolicy>().Where(n => n is not (nameof(PinPolicy.Unknown) or nameof(PinPolicy.Never))).ToList();

    public static readonly IReadOnlyList<string> TouchPolicies =
        Enum.GetNames<TouchPolicy>().Where(n => n != nameof(TouchPolicy.Unknown)).ToList();

    [GeneratedRegex("^[a-z0-9][a-z0-9-]{1,63}$")]
    private static partial Regex ProfileName();

    [GeneratedRegex(@"^[0-2](\.(0|[1-9][0-9]*))+$")]
    private static partial Regex Oid();

    // ------------------------------------------------------------------ CAs

    public IReadOnlyList<CaInstanceView> Instances()
    {
        using var session = database.OpenSession();
        var rows = session.Query<CaInstance>().OrderBy(c => c.CreatedAt).ToList();
        var used = session.Query<CertificateProfile>().Select(p => p.CaInstance.Id).ToList();
        var defaultId = rows.FirstOrDefault(r => r.IsEnabled)?.Id;

        return rows.Select(r => View(r, used.Count(id => id == r.Id), r.Id == defaultId)).ToList();
    }

    public CaInstanceView Create(CaInstanceRequest request, string actor)
    {
        using var session = database.OpenSession();
        using var transaction = session.BeginTransaction();

        var name = Required(request.Name, "a CA needs a name").Trim();
        if (session.Query<CaInstance>().Any(c => c.Name == name))
        {
            throw new CaAdministrationException(409, $"There is already a CA called {name}.");
        }

        var now = DateTime.UtcNow;
        var row = new CaInstance
        {
            Name = name,
            Backend = request.Backend,
            Topology = CaTopology.TwoTier,
            CreatedAt = now,
            UpdatedAt = now,
        };

        Apply(row, request, session);
        session.Save(row);
        session.Save(Audit(now, actor, "ca.created", nameof(CaInstance), row.Id, new { row.Name, backend = row.Backend.ToString() }));
        transaction.Commit();

        authorities.Forget();
        return View(row, 0, false);
    }

    public CaInstanceView Update(Guid id, CaInstanceRequest request, string actor)
    {
        using var session = database.OpenSession();
        using var transaction = session.BeginTransaction();

        var row = session.Get<CaInstance>(id) ?? throw new CaAdministrationException(404, "There is no such CA.");

        // A row's backend is what its credentials were issued by. Turning an ADCS row
        // into a built-in one would rewrite the history of every credential under it.
        if (request.Backend != row.Backend)
        {
            throw new CaAdministrationException(409,
                "A CA's backend cannot change: credentials issued under it would then claim another issuer. Add a new CA.");
        }

        var name = Required(request.Name, "a CA needs a name").Trim();
        if (name != row.Name && session.Query<CaInstance>().Any(c => c.Name == name))
        {
            throw new CaAdministrationException(409, $"There is already a CA called {name}.");
        }

        row.Name = name;
        Apply(row, request, session);
        row.UpdatedAt = DateTime.UtcNow;
        session.Update(row);
        session.Save(Audit(row.UpdatedAt, actor, "ca.updated", nameof(CaInstance), row.Id, new { row.Name, row.IsEnabled }));
        transaction.Commit();

        authorities.Forget();
        return View(row, session.Query<CertificateProfile>().Count(p => p.CaInstance.Id == id), false);
    }

    public void DeleteInstance(Guid id, string actor)
    {
        using var session = database.OpenSession();
        using var transaction = session.BeginTransaction();

        var row = session.Get<CaInstance>(id) ?? throw new CaAdministrationException(404, "There is no such CA.");

        if (session.Query<CertificateProfile>().Any(p => p.CaInstance.Id == id))
        {
            throw new CaAdministrationException(409,
                $"{row.Name} still has profiles. Point them at another CA or delete them first.");
        }

        if (session.Query<Credential>().Any(c => c.CaInstance != null && c.CaInstance.Id == id))
        {
            throw new CaAdministrationException(409,
                $"Credentials were issued by {row.Name}, and they keep saying so. Disable it instead.");
        }

        session.Delete(row);
        session.Save(Audit(DateTime.UtcNow, actor, "ca.deleted", nameof(CaInstance), id, new { row.Name }));
        transaction.Commit();

        authorities.Forget();
    }

    /// <summary>Asks the CA what it is - through the connector for ADCS - without issuing anything.</summary>
    public async Task<object> TestAsync(Guid id, CancellationToken ct)
    {
        var capabilities = await authorities.For(id).DescribeAsync(ct);

        return new
        {
            backend = capabilities.Backend.ToString(),
            canIssueLogonCredentials = capabilities.CanIssueSmartCardLogon,
            supportsRevocation = capabilities.SupportsRevocation,
            algorithms = capabilities.Algorithms.Select(a => a.ToString()),
        };
    }

    private void Apply(CaInstance row, CaInstanceRequest request, NHibernate.ISession session)
    {
        row.IsEnabled = request.IsEnabled;

        if (row.Backend == CaBackend.Adcs)
        {
            var given = request.Adcs ?? throw new CaAdministrationException(400, "A Microsoft CA needs its connector settings.");
            var options = CertificateAuthorities.AdcsSettingsOf(row);

            options.Transport = given.Transport switch
            {
                "Connector" or "ConnectorPolls" => given.Transport,
                _ => throw new CaAdministrationException(400, "The transport is Connector or ConnectorPolls."),
            };
            options.Connector.CaConfig = Blank(given.CaConfig);
            options.Connector.Url = Blank(given.ConnectorUrl);
            options.Connector.ServerFingerprint = Blank(given.ServerFingerprint);
            options.Connector.ClientCertificatePath = Blank(given.ClientCertificatePath);
            options.Connector.ClientCertificatePasswordFile = Blank(given.ClientCertificatePasswordFile);
            options.Connector.TimeoutSeconds = given.TimeoutSeconds is > 0 and <= 600 ? given.TimeoutSeconds.Value : 90;
            options.AllowRevocation = given.AllowRevocation;
            options.KeyAlgorithms = (given.KeyAlgorithms ?? []).Select(KeyAlgorithm).Distinct().ToList();

            // One connector collects from this API's queue. Two enabled rows polling it
            // would hand each other's calls to whichever connector asked first.
            if (row.IsEnabled && options.Transport == "ConnectorPolls"
                && session.Query<CaInstance>().ToList().Any(c => c.Id != row.Id && c.IsEnabled
                    && c.Backend == CaBackend.Adcs
                    && CertificateAuthorities.AdcsSettingsOf(c).Transport == "ConnectorPolls"))
            {
                throw new CaAdministrationException(409,
                    "Another enabled CA already uses the polling connector, and there is one queue for one connector.");
            }

            row.Configuration = CertificateAuthorities.Serialise(options);
        }
        else
        {
            row.Configuration = JsonSerializer.Serialize(
                new BuiltInSettings(Blank(request.BuiltInDirectory)), CertificateAuthorities.Json);
        }

        // Built once here so that a wrong URL, a missing pin or an unreadable CA
        // directory is refused in front of whoever typed it, not at somebody's
        // enrolment. Nothing here reaches the CA itself.
        try
        {
            CertificateAuthorities.Build(row, [], configuration, queue);
        }
        catch (Exception ex) when (ex is CertificateAuthorityException or InvalidOperationException
                                       or IOException or System.Security.Cryptography.CryptographicException)
        {
            throw new CaAdministrationException(400, ex.Message);
        }
    }

    private static CaInstanceView View(CaInstance row, int profiles, bool isDefault)
    {
        AdcsSettingsView? adcs = null;

        if (row.Backend == CaBackend.Adcs)
        {
            var o = CertificateAuthorities.AdcsSettingsOf(row);
            adcs = new AdcsSettingsView(o.Transport, o.Connector.CaConfig, o.Connector.Url, o.Connector.ServerFingerprint,
                o.Connector.ClientCertificatePath, o.Connector.ClientCertificatePasswordFile, o.Connector.TimeoutSeconds,
                o.AllowRevocation, o.KeyAlgorithms);
        }

        return new CaInstanceView(row.Id, row.Name, row.Backend.ToString(), row.IsEnabled, isDefault, profiles,
            adcs, row.Backend == CaBackend.BuiltIn ? CertificateAuthorities.BuiltInSettingsOf(row).Directory : null,
            row.CreatedAt, row.UpdatedAt);
    }

    // ------------------------------------------------------------------ profiles

    public IReadOnlyList<ProfileView> Profiles(bool enabledOnly = false)
    {
        using var session = database.OpenSession();
        var rows = session.Query<CertificateProfile>().Fetch(p => p.CaInstance).OrderBy(p => p.Name).ToList();
        return rows.Where(p => !enabledOnly || (p.IsEnabled && p.CaInstance.IsEnabled)).Select(View).ToList();
    }

    /// <summary>The enabled profile by name, with its CA, for the enrolment that names it.</summary>
    public CertificateProfile? Find(string name)
    {
        using var session = database.OpenSession();
        return session.Query<CertificateProfile>().Fetch(p => p.CaInstance)
            .FirstOrDefault(p => p.Name == name && p.IsEnabled && p.CaInstance.IsEnabled);
    }

    public ProfileView CreateProfile(ProfileRequest request, string actor)
    {
        using var session = database.OpenSession();
        using var transaction = session.BeginTransaction();

        var name = Required(request.Name, "a profile needs a name").Trim();
        if (!ProfileName().IsMatch(name))
        {
            throw new CaAdministrationException(400,
                "A profile's name is lower-case letters, digits and hyphens: it travels in every enrolment job.");
        }

        if (session.Query<CertificateProfile>().Any(p => p.Name == name))
        {
            throw new CaAdministrationException(409, $"There is already a profile called {name}.");
        }

        var now = DateTime.UtcNow;
        var row = new CertificateProfile { Name = name, CreatedAt = now };
        Apply(row, request, session);
        row.UpdatedAt = now;

        session.Save(row);
        session.Save(Audit(now, actor, "profile.created", nameof(CertificateProfile), row.Id, new { row.Name, ca = row.CaInstance.Name }));
        transaction.Commit();

        authorities.Forget();
        return View(row);
    }

    public ProfileView UpdateProfile(Guid id, ProfileRequest request, string actor)
    {
        using var session = database.OpenSession();
        using var transaction = session.BeginTransaction();

        var row = session.Get<CertificateProfile>(id) ?? throw new CaAdministrationException(404, "There is no such profile.");

        // The name is fixed: a pending enrolment job carries it, and renaming the
        // profile under the job would make the job name nothing.
        if (request.Name is { Length: > 0 } renamed && renamed.Trim() != row.Name)
        {
            throw new CaAdministrationException(409,
                "A profile's name cannot change: enrolment jobs carry it. Create a new profile and disable this one.");
        }

        Apply(row, request, session);
        row.UpdatedAt = DateTime.UtcNow;
        session.Update(row);
        session.Save(Audit(row.UpdatedAt, actor, "profile.updated", nameof(CertificateProfile), row.Id,
            new { row.Name, ca = row.CaInstance.Name, row.AdcsTemplateName, row.IsEnabled }));
        transaction.Commit();

        authorities.Forget();
        return View(row);
    }

    public void DeleteProfile(Guid id, string actor)
    {
        using var session = database.OpenSession();
        using var transaction = session.BeginTransaction();

        var row = session.Get<CertificateProfile>(id) ?? throw new CaAdministrationException(404, "There is no such profile.");

        if (session.Query<Credential>().Any(c => c.Profile != null && c.Profile.Id == id))
        {
            throw new CaAdministrationException(409,
                $"Credentials were issued under {row.Name}, and they keep saying so. Disable it instead.");
        }

        session.Delete(row);
        session.Save(Audit(DateTime.UtcNow, actor, "profile.deleted", nameof(CertificateProfile), id, new { row.Name }));
        transaction.Commit();

        authorities.Forget();
    }

    private static void Apply(CertificateProfile row, ProfileRequest request, NHibernate.ISession session)
    {
        row.CaInstance = session.Get<CaInstance>(request.CaInstanceId)
                         ?? throw new CaAdministrationException(400, "The profile names a CA that does not exist.");

        row.SlotId = Slots.Contains(request.SlotId?.ToUpperInvariant() ?? string.Empty)
            ? request.SlotId!.ToUpperInvariant()
            : throw new CaAdministrationException(400, $"The slot is one of {string.Join(", ", Slots)}.");

        row.KeyAlgorithm = KeyAlgorithm(request.KeyAlgorithm);

        row.ValidityDays = request.ValidityDays is >= 1 and <= 3650
            ? request.ValidityDays
            : throw new CaAdministrationException(400, "Validity is between 1 and 3650 days.");

        var ekus = (request.ExtendedKeyUsages ?? []).Select(e => e.Trim()).Where(e => e.Length > 0).Distinct().ToList();
        if (ekus.Count == 0 || ekus.Any(e => !Oid().IsMatch(e)))
        {
            throw new CaAdministrationException(400, "Extended key usages are object identifiers, at least one.");
        }

        row.ExtendedKeyUsages = JsonSerializer.Serialize(ekus);
        row.IncludeUpnSan = request.IncludeUpnSan;
        row.IncludeSidExtension = request.IncludeSidExtension;
        row.Description = Blank(request.Description);
        row.AdcsTemplateName = Blank(request.AdcsTemplateName);
        row.RequiredPinPolicy = Policy(request.RequiredPinPolicy, PinPolicies, "PIN policy");
        row.RequiredTouchPolicy = Policy(request.RequiredTouchPolicy, TouchPolicies, "touch policy");
        row.IsEnabled = request.IsEnabled;

        // A Microsoft CA issues against a template and nothing else; without one the
        // first enrolment would fail at the CA with a sentence about configuration.
        if (row.CaInstance.Backend == CaBackend.Adcs && row.AdcsTemplateName is null)
        {
            throw new CaAdministrationException(400,
                "A profile on a Microsoft CA needs the template's name - the name, not its display name.");
        }
    }

    private static ProfileView View(CertificateProfile p) => new(
        p.Id, p.Name, p.Description, p.CaInstance.Id, p.CaInstance.Name, p.CaInstance.Backend.ToString(),
        p.SlotId, p.KeyAlgorithm, p.ValidityDays,
        JsonSerializer.Deserialize<List<string>>(p.ExtendedKeyUsages) ?? [],
        p.IncludeUpnSan, p.IncludeSidExtension, p.AdcsTemplateName, p.RequiredPinPolicy, p.RequiredTouchPolicy,
        p.IsEnabled, p.UpdatedAt);

    // ------------------------------------------------------------------ helpers

    public static string KeyAlgorithm(string? given)
    {
        var match = KeyAlgorithms.FirstOrDefault(a => string.Equals(a, given?.Trim(), StringComparison.OrdinalIgnoreCase));
        return match ?? throw new CaAdministrationException(400,
            $"The key algorithm is one of {string.Join(", ", KeyAlgorithms)}.");
    }

    private static string? Policy(string? given, IReadOnlyList<string> allowed, string what)
    {
        if (string.IsNullOrWhiteSpace(given))
        {
            return null;
        }

        return allowed.FirstOrDefault(a => string.Equals(a, given.Trim(), StringComparison.OrdinalIgnoreCase))
               ?? throw new CaAdministrationException(400, $"The {what} is one of {string.Join(", ", allowed)}, or none.");
    }

    private static string Required(string? value, string message) =>
        string.IsNullOrWhiteSpace(value) ? throw new CaAdministrationException(400, message) : value;

    private static string? Blank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static AuditEvent Audit(DateTime now, string actor, string type, string subjectType, Guid id, object detail) => new()
    {
        OccurredAt = now,
        EventType = type,
        Actor = actor,
        SubjectType = subjectType,
        SubjectId = id,
        Detail = JsonSerializer.Serialize(detail),
    };
}

public sealed class CaAdministrationException(int status, string message) : Exception(message)
{
    public int Status { get; } = status;
}

public sealed record AdcsSettingsRequest(
    string Transport,
    string? CaConfig,
    string? ConnectorUrl,
    string? ServerFingerprint,
    string? ClientCertificatePath,
    string? ClientCertificatePasswordFile,
    int? TimeoutSeconds,
    bool AllowRevocation,
    IReadOnlyList<string>? KeyAlgorithms);

public sealed record CaInstanceRequest(
    string? Name,
    CaBackend Backend,
    bool IsEnabled,
    AdcsSettingsRequest? Adcs,
    string? BuiltInDirectory);

public sealed record AdcsSettingsView(
    string Transport,
    string? CaConfig,
    string? ConnectorUrl,
    string? ServerFingerprint,
    string? ClientCertificatePath,
    string? ClientCertificatePasswordFile,
    int TimeoutSeconds,
    bool AllowRevocation,
    IReadOnlyList<string> KeyAlgorithms);

public sealed record CaInstanceView(
    Guid Id,
    string Name,
    string Backend,
    bool IsEnabled,
    bool IsDefault,
    int Profiles,
    AdcsSettingsView? Adcs,
    string? BuiltInDirectory,
    DateTime CreatedAt,
    DateTime UpdatedAt);

public sealed record ProfileRequest(
    string? Name,
    string? Description,
    Guid CaInstanceId,
    string? SlotId,
    string? KeyAlgorithm,
    int ValidityDays,
    IReadOnlyList<string>? ExtendedKeyUsages,
    bool IncludeUpnSan,
    bool IncludeSidExtension,
    string? AdcsTemplateName,
    string? RequiredPinPolicy,
    string? RequiredTouchPolicy,
    bool IsEnabled);

public sealed record ProfileView(
    Guid Id,
    string Name,
    string? Description,
    Guid CaInstanceId,
    string CaInstanceName,
    string Backend,
    string SlotId,
    string KeyAlgorithm,
    int ValidityDays,
    IReadOnlyList<string> ExtendedKeyUsages,
    bool IncludeUpnSan,
    bool IncludeSidExtension,
    string? AdcsTemplateName,
    string? RequiredPinPolicy,
    string? RequiredTouchPolicy,
    bool IsEnabled,
    DateTime UpdatedAt);
