using System.Text.Json;
using System.Text.RegularExpressions;
using Blinky.Api.Persistence;
using Blinky.Domain;
using Blinky.Domain.Entities;
using Blinky.Passkeys;
using Blinky.Passkeys.Entra;
using Blinky.Passkeys.Okta;
using NHibernate.Linq;

namespace Blinky.Api.Passkeys;

/// <summary>What the provider configuration reads and writes.</summary>
public interface IPasskeyProviderStore
{
    IReadOnlyList<PasskeyProvider> All();

    PasskeyProvider? Get(Guid id);

    bool NameTaken(string name);

    /// <summary>Whether passkeys registered through this provider still exist there.</summary>
    bool HasRegisteredPasskeys(string name);

    void Save(PasskeyProvider row, AuditEvent audit);

    void Delete(PasskeyProvider row, AuditEvent audit);
}

public sealed class PasskeyProviderStore(Database database) : IPasskeyProviderStore
{
    public IReadOnlyList<PasskeyProvider> All()
    {
        using var session = database.OpenSession();
        return session.Query<PasskeyProvider>().OrderBy(p => p.Name).ToList();
    }

    public PasskeyProvider? Get(Guid id)
    {
        using var session = database.OpenSession();
        return session.Get<PasskeyProvider>(id);
    }

    public bool NameTaken(string name)
    {
        using var session = database.OpenSession();
        return session.Query<PasskeyProvider>().Any(p => p.Name == name);
    }

    public bool HasRegisteredPasskeys(string name)
    {
        using var session = database.OpenSession();
        return session.Query<PasskeyCredential>()
            .Any(p => p.Directory == name && p.State == PasskeyCredentialState.Registered);
    }

    public void Save(PasskeyProvider row, AuditEvent audit)
    {
        using var session = database.OpenSession();
        using var transaction = session.BeginTransaction();
        session.SaveOrUpdate(row);
        audit.SubjectId ??= row.Id;
        session.Save(audit);
        transaction.Commit();
    }

    public void Delete(PasskeyProvider row, AuditEvent audit)
    {
        using var session = database.OpenSession();
        using var transaction = session.BeginTransaction();
        session.Delete(session.Get<PasskeyProvider>(row.Id));
        session.Save(audit);
        transaction.Commit();
    }
}

/// <summary>A provider's settings as the console sends them. Never a credential.</summary>
public sealed record PasskeyProviderRequest(
    string? Name,
    PasskeyProviderKind Kind,
    bool IsEnabled = true,
    string? TenantId = null,
    string? ClientId = null,
    string? OrgUrl = null,
    string? KeyId = null,
    string? Authority = null,
    string? GraphUrl = null,
    int ChallengeMinutes = 10);

/// <summary>A credential the administrator brought, to be sealed and forgotten by the request.</summary>
public sealed record PasskeyCredentialImport(PasskeyProviderCredential Kind, string Value, string? Password = null);

/// <summary>A provider as the console sees it: everything except the credential itself.</summary>
public sealed record PasskeyProviderView(
    Guid Id,
    string Name,
    PasskeyProviderKind Kind,
    bool IsEnabled,
    string? TenantId,
    string? ClientId,
    string? OrgUrl,
    string? KeyId,
    string? Authority,
    string? GraphUrl,
    int ChallengeMinutes,
    PasskeyProviderCredential? CredentialKind,
    bool CredentialSet,
    string? CredentialHint,
    string? PublicMaterial,
    DateTime? CredentialExpiresAt,
    DateTime? CredentialSetAt,
    string? CredentialSetBy,
    bool HasRegisteredPasskeys,
    string? Problem);

/// <summary>
/// The passkey providers, configured in the console and kept in the database (0107).
/// </summary>
/// <remarks>
/// Owns the registry the ceremony uses, so that a change here is a change there on
/// the next call: saving a provider drops the built set, and the next lookup builds
/// it again from the rows. A provider that cannot be built - no credential, a
/// credential that will not open - is left out and its problem is shown on its row,
/// rather than taking every other provider down with it.
/// </remarks>
public sealed partial class PasskeyProviders
{
    private readonly IPasskeyProviderStore store;
    private readonly ProviderSecrets secrets;
    private readonly ILogger<PasskeyProviders> logger;
    private readonly TimeProvider time;
    private readonly HttpClient http = new() { Timeout = TimeSpan.FromSeconds(30) };
    private readonly Dictionary<Guid, string> problems = [];

    public PasskeyProviders(IPasskeyProviderStore store, ProviderSecrets secrets, ILogger<PasskeyProviders> logger,
        TimeProvider? time = null)
    {
        this.store = store;
        this.secrets = secrets;
        this.logger = logger;
        this.time = time ?? TimeProvider.System;
        Directories = new PasskeyDirectories(Build);
    }

    public PasskeyDirectories Directories { get; }

    private DateTime Now => time.GetUtcNow().UtcDateTime;

    public IReadOnlyList<PasskeyProviderView> List()
    {
        _ = Directories.All; // built, so the problems are current

        return store.All().Select(View).ToList();
    }

    public PasskeyProviderView Create(PasskeyProviderRequest request, string actor)
    {
        var name = (request.Name ?? "").Trim().ToLowerInvariant();

        if (!NamePattern().IsMatch(name))
        {
            throw new PasskeyFlowException(400, "bad-name",
                "A name is 1 to 40 lower-case letters, digits and hyphens - it appears in URLs and in every passkey row.");
        }

        if (store.NameTaken(name))
        {
            throw new PasskeyFlowException(409, "name-taken", $"A provider called {name} already exists.");
        }

        var now = Now;
        var row = new PasskeyProvider { Name = name, Kind = request.Kind, CreatedAt = now, UpdatedAt = now };
        Apply(row, request);

        store.Save(row, Audit("passkey-provider.created", actor, row, new { name, kind = request.Kind.ToString() }));
        Directories.Invalidate();
        return View(row);
    }

    /// <summary>Settings only. The name and the kind stay what they were created as.</summary>
    public PasskeyProviderView Update(Guid id, PasskeyProviderRequest request, string actor)
    {
        var row = Find(id);

        if (request.Kind != row.Kind)
        {
            throw new PasskeyFlowException(400, "kind-fixed",
                "A provider's kind is fixed once created. Make a new provider instead.");
        }

        Apply(row, request);
        row.UpdatedAt = Now;

        store.Save(row, Audit("passkey-provider.updated", actor, row, new { enabled = row.IsEnabled }));
        Directories.Invalidate();
        return View(row);
    }

    /// <summary>
    /// Refused while passkeys registered through it still exist: deleting it would
    /// leave them unrevokable from here. Disable it instead.
    /// </summary>
    public void Delete(Guid id, string actor)
    {
        var row = Find(id);

        if (store.HasRegisteredPasskeys(row.Name))
        {
            throw new PasskeyFlowException(409, "in-use",
                $"Passkeys registered through {row.Name} still exist; revoke them first, or disable the provider.");
        }

        store.Delete(row, Audit("passkey-provider.deleted", actor, row, new { name = row.Name }));
        Directories.Invalidate();
    }

    /// <summary>
    /// Blinky makes the key, seals it, and hands back only the public half for the
    /// administrator to give the provider.
    /// </summary>
    public PasskeyProviderView GenerateCredential(Guid id, string actor) =>
        SetCredential(id, ProviderMaterial.Generate(Find(id).Kind, Find(id).Name, Now), actor, generated: true);

    public PasskeyProviderView ImportCredential(Guid id, PasskeyCredentialImport import, string actor)
    {
        var row = Find(id);

        try
        {
            return SetCredential(id, ProviderMaterial.Import(row.Kind, import.Kind, import.Value, import.Password),
                actor, generated: false);
        }
        catch (Exception e) when (e is ArgumentException or FormatException or System.Security.Cryptography.CryptographicException)
        {
            throw new PasskeyFlowException(400, "bad-credential", e.Message);
        }
    }

    /// <summary>
    /// Builds the provider and asks it for something harmless - a user who does not
    /// exist. A token refused, a consent missing, a URL wrong: each says so here,
    /// before anybody plugs in a key.
    /// </summary>
    public async Task<string> TestAsync(Guid id, CancellationToken ct)
    {
        var row = Find(id);
        var directory = BuildOne(row);

        try
        {
            await directory.FindUserAsync($"blinky-connection-test-{Guid.NewGuid():N}@invalid", ct);
            return "The provider answered and accepted Blinky's credential.";
        }
        catch (PasskeyDirectoryException e)
        {
            throw new PasskeyFlowException(502, "provider", e.Message);
        }
    }

    private PasskeyProviderView SetCredential(Guid id, PreparedCredential prepared, string actor, bool generated)
    {
        var row = Find(id);
        secrets.Seal(row, prepared.Kind, prepared.Secret);

        var now = Now;
        row.PublicMaterial = prepared.PublicMaterial;
        row.CredentialHint = prepared.Hint;
        row.CredentialExpiresAt = prepared.ExpiresAt;
        row.CredentialSetAt = now;
        row.CredentialSetBy = actor;
        row.UpdatedAt = now;

        if (prepared.KeyId is { } kid)
        {
            row.KeyId = kid;
        }

        // The hint and how it was made, never the credential.
        store.Save(row, Audit("passkey-provider.credential-set", actor, row,
            new { kind = prepared.Kind.ToString(), hint = prepared.Hint, generated }));
        Directories.Invalidate();
        return View(row);
    }

    private IReadOnlyList<IPasskeyDirectory> Build()
    {
        var built = new List<IPasskeyDirectory>();

        lock (problems)
        {
            problems.Clear();

            foreach (var row in store.All().Where(r => r.IsEnabled))
            {
                try
                {
                    built.Add(BuildOne(row));
                }
                catch (Exception e)
                {
                    problems[row.Id] = e.Message;
                    logger.LogWarning("Passkey provider {Name} is configured but cannot be used: {Problem}",
                        row.Name, e.Message);
                }
            }
        }

        logger.LogInformation("Passkey providers: {Providers}",
            built.Count == 0 ? "none usable" : string.Join(", ", built.Select(d => d.Name)));

        return built;
    }

    private IPasskeyDirectory BuildOne(PasskeyProvider row)
    {
        if (row.CredentialKind is not { } kind)
        {
            throw new PasskeyFlowException(409, "no-credential",
                "No credential is set. Generate one, or import one, before the provider can be used.");
        }

        var secret = secrets.Open(row);

        return row.Kind switch
        {
            PasskeyProviderKind.Entra => EntraPasskeyDirectory.Create(
                new EntraOptions(row.TenantId!, row.ClientId!, row.Name,
                    row.Authority ?? "https://login.microsoftonline.com",
                    row.GraphUrl ?? "https://graph.microsoft.com",
                    row.ChallengeMinutes),
                ProviderMaterial.EntraCredential(kind, secret), http),
            PasskeyProviderKind.Okta when kind is PasskeyProviderCredential.ApiToken =>
                OktaPasskeyDirectory.WithApiToken(
                    new OktaOptions(row.OrgUrl!, row.ClientId, row.KeyId, row.Name, row.ChallengeMinutes), secret, http),
            PasskeyProviderKind.Okta => OktaPasskeyDirectory.WithPrivateKey(
                new OktaOptions(row.OrgUrl!, row.ClientId, row.KeyId, row.Name, row.ChallengeMinutes),
                ProviderMaterial.Key(secret), http),
            _ => throw new InvalidOperationException($"Unknown provider kind {row.Kind}."),
        };
    }

    private static void Apply(PasskeyProvider row, PasskeyProviderRequest request)
    {
        string? Clean(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

        if (request.ChallengeMinutes is < 5 or > 60)
        {
            throw new PasskeyFlowException(400, "bad-challenge",
                "The challenge lifetime is 5 to 60 minutes: Graph refuses less, and more is a challenge left lying about.");
        }

        if (row.Kind is PasskeyProviderKind.Entra)
        {
            if (Clean(request.TenantId) is null || !Guid.TryParse(request.ClientId, out _))
            {
                throw new PasskeyFlowException(400, "bad-entra",
                    "Entra needs the directory (tenant) id and the application (client) id, a GUID.");
            }

            Https(request.Authority, "authority");
            Https(request.GraphUrl, "Graph");
        }
        else
        {
            var url = Clean(request.OrgUrl) ?? "";
            var withScheme = url.Contains("://", StringComparison.Ordinal) ? url : $"https://{url}";

            if (url.Length == 0 || !Uri.TryCreate(withScheme, UriKind.Absolute, out var org)
                || org.Scheme != Uri.UriSchemeHttps)
            {
                throw new PasskeyFlowException(400, "bad-okta",
                    "Okta needs the https URL users sign in at - the org's own domain or its custom one.");
            }
        }

        row.IsEnabled = request.IsEnabled;
        row.TenantId = Clean(request.TenantId);
        row.ClientId = Clean(request.ClientId);
        row.OrgUrl = Clean(request.OrgUrl);
        row.KeyId = Clean(request.KeyId) ?? row.KeyId;
        row.Authority = Clean(request.Authority);
        row.GraphUrl = Clean(request.GraphUrl);
        row.ChallengeMinutes = request.ChallengeMinutes;
    }

    private static void Https(string? value, string what)
    {
        if (!string.IsNullOrWhiteSpace(value)
            && !(Uri.TryCreate(value.Trim(), UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps))
        {
            throw new PasskeyFlowException(400, "bad-url", $"The {what} endpoint has to be an https URL.");
        }
    }

    private PasskeyProvider Find(Guid id) =>
        store.Get(id) ?? throw new PasskeyFlowException(404, "no-such-provider", "No such passkey provider.");

    private PasskeyProviderView View(PasskeyProvider row)
    {
        string? problem;

        lock (problems)
        {
            problem = problems.GetValueOrDefault(row.Id);
        }

        return new PasskeyProviderView(row.Id, row.Name, row.Kind, row.IsEnabled, row.TenantId, row.ClientId,
            row.OrgUrl, row.KeyId, row.Authority, row.GraphUrl, row.ChallengeMinutes, row.CredentialKind,
            row.SecretCiphertext is not null, row.CredentialHint, row.PublicMaterial, row.CredentialExpiresAt,
            row.CredentialSetAt, row.CredentialSetBy, store.HasRegisteredPasskeys(row.Name),
            row.IsEnabled ? problem : null);
    }

    private AuditEvent Audit(string type, string actor, PasskeyProvider row, object detail) => new()
    {
        OccurredAt = Now,
        EventType = type,
        Actor = actor,
        SubjectType = nameof(PasskeyProvider),
        SubjectId = row.Id == Guid.Empty ? null : row.Id,
        Detail = JsonSerializer.Serialize(detail),
    };

    [GeneratedRegex("^[a-z0-9][a-z0-9-]{0,39}$")]
    private static partial Regex NamePattern();
}
