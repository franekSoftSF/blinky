using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Blinky.Passkeys.Okta;

public enum OktaAuthMode
{
    /// <summary>An SSWS API token. Acts as the admin who created it, and never expires on its own.</summary>
    ApiToken,

    /// <summary>A service app with <c>private_key_jwt</c>. For anything that is not a lab.</summary>
    OAuthPrivateKeyJwt,
}

/// <param name="OrgUrl">
/// The org's URL - <c>https://acme.okta.com</c> or its custom domain. Credentials
/// are bound to the domain they were created on, so this has to be the domain users
/// sign in at, not the admin one.
/// </param>
/// <param name="PrivateKeyPath">PEM, RSA or P-256, PKCS#8 or traditional.</param>
/// <param name="KeyId">The <c>kid</c> Okta shows for the key; needed once an app has two.</param>
/// <param name="ChallengeMinutes">
/// Okta does not say when an activation expires. This is Blinky's own deadline for
/// the job, not a promise about Okta's.
/// </param>
public sealed record OktaOptions(
    string OrgUrl,
    OktaAuthMode AuthMode = OktaAuthMode.OAuthPrivateKeyJwt,
    string? ApiToken = null,
    string? ClientId = null,
    string? PrivateKeyPath = null,
    string? KeyId = null,
    string Name = "okta",
    int ChallengeMinutes = 5);

/// <summary>
/// Okta's Factors API: enrol a <c>webauthn</c> factor for a user, activate it with
/// the attestation. The route an admin's "Enroll FIDO2 Security Key" button takes.
/// </summary>
/// <remarks>
/// The one provider KeyEnroll has proved on hardware (Okta, USB key, Windows ARM64),
/// and the reason two of the details below are the way they are rather than the way
/// brief 12 guessed: the user handle and the base64 flavour of the activation.
/// </remarks>
public sealed class OktaPasskeyDirectory : IPasskeyDirectory
{
    private const string Label = "Okta";

    private readonly OktaOptions options;
    private readonly ProviderHttp http;
    private readonly TimeProvider time;
    private readonly Uri org;

    public OktaPasskeyDirectory(OktaOptions options, HttpClient client,
        IProviderAuthorization authorization, TimeProvider? time = null)
    {
        this.options = options;
        this.time = time ?? TimeProvider.System;
        org = OrgUri(options.OrgUrl);
        http = new ProviderHttp(client, authorization, Label, ErrorDetail, this.time);
    }

    public static OktaPasskeyDirectory Create(OktaOptions options, HttpClient client, TimeProvider? time = null)
    {
        IProviderAuthorization authorization = options.AuthMode switch
        {
            OktaAuthMode.ApiToken when options.ApiToken is { Length: > 0 } token =>
                new StaticAuthorization("SSWS", token),
            OktaAuthMode.ApiToken =>
                throw new PasskeyAuthorizationException("Okta is set to ApiToken and no token is configured."),
            _ when options is { ClientId.Length: > 0, PrivateKeyPath.Length: > 0 } =>
                new ClientCredentialsAuthorization(client,
                    new Uri(OrgUri(options.OrgUrl), "/oauth2/v1/token"),
                    options.ClientId,
                    "okta.users.read okta.users.manage",
                    ClientCredential.PrivateKey(LoadKey(options.PrivateKeyPath), options.KeyId),
                    time),
            _ => throw new PasskeyAuthorizationException(
                "Okta is set to OAuthPrivateKeyJwt and needs both a client id and a private key."),
        };

        return new OktaPasskeyDirectory(options, client, authorization, time);
    }

    private static AsymmetricAlgorithm LoadKey(string path)
    {
        var pem = File.ReadAllText(path);

        // PKCS#8 does not say which algorithm it holds until it is parsed.
        try
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(pem);
            return rsa;
        }
        catch (Exception e) when (e is CryptographicException or ArgumentException)
        {
            var ec = ECDsa.Create();
            ec.ImportFromPem(pem);
            return ec;
        }
    }

    private static Uri OrgUri(string value)
    {
        var text = value.Trim();
        var uri = new Uri(text.Contains("://", StringComparison.Ordinal) ? text : $"https://{text}");

        return new Uri($"https://{uri.IdnHost.ToLowerInvariant()}{(uri.IsDefaultPort ? "" : $":{uri.Port}")}");
    }

    public string Name => options.Name;

    /// <summary>Okta names the key itself, from the authenticator's AAGUID.</summary>
    public PasskeyCapabilities Capabilities { get; } = new(
        SupportsRegistration: true,
        PrepareOnly: false,
        PinDeliveryByProvider: false,
        AcceptsDisplayName: false,
        MaxDisplayNameLength: null);

    public async Task<PasskeyUser?> FindUserAsync(string identifier, CancellationToken ct = default)
    {
        try
        {
            // An id, a login, or a short login when it is unambiguous - Okta decides.
            using var found = await http.GetAsync(
                new Uri(org, $"/api/v1/users/{Uri.EscapeDataString(identifier.Trim())}"), ct);
            return found is null ? null : ToUser(found.RootElement);
        }
        catch (PasskeyDirectoryException e) when (e.Status == 404)
        {
            return null;
        }
    }

    public async Task<PendingRegistration> BeginRegistrationAsync(PasskeyUser user, CancellationToken ct = default)
    {
        using var factor = await http.PostAsync(FactorsUrl(user.Id),
            new { factorType = "webauthn", provider = "FIDO" }, ct)
            ?? throw new PasskeyDirectoryException($"{Label}: enrolling a factor returned nothing.");

        var root = factor.RootElement;
        var factorId = Json.Text(root, "id")
            ?? throw new PasskeyDirectoryException($"{Label}: the enrolled factor has no id.");

        try
        {
            var activation = Json.Child(root, "_embedded") is { } embedded
                ? Json.Required(embedded, "activation", Label)
                : throw new PasskeyDirectoryException($"{Label}: the factor carries no activation data.");

            var creation = CreationOptionsReader.Read(
                activation,
                Label,
                rpIdFallback: org.Host,
                userHandle: UserHandle,
                origin: Origin,
                time.GetUtcNow().AddMinutes(options.ChallengeMinutes));

            return new PendingRegistration(user, creation, factorId);
        }
        catch
        {
            // The factor exists now, pending, whether or not its options could be
            // read. Left behind, it is what the next attempt for this user trips on.
            await TryDeleteAsync(user.Id, factorId);
            throw;
        }
    }

    public async Task<RegisteredPasskey> CompleteRegistrationAsync(RegistrationHandle pending,
        AttestationResponse response, string displayName, CancellationToken ct = default)
    {
        var factorId = pending.ProviderReference
            ?? throw new ArgumentException("An Okta registration carries its factor id.", nameof(pending));

        // Standard base64, padded - not base64url, whatever brief 12 says. This is
        // the form KeyEnroll sends in the one ceremony proved against a real org.
        var body = new
        {
            attestation = Convert.ToBase64String(response.AttestationObject),
            clientData = Convert.ToBase64String(response.ClientDataJson),
        };

        using var activated = await http.PostAsync(
            new Uri($"{FactorsUrl(pending.User.Id)}/{Uri.EscapeDataString(factorId)}/lifecycle/activate"),
            body, ct);

        var status = activated is null ? null : Json.Text(activated.RootElement, "status");

        if (status is not null && status != "ACTIVE")
        {
            throw new PasskeyDirectoryException($"{Label}: the factor was left {status} after activation.");
        }

        return new RegisteredPasskey(factorId, activated is null ? null : Json.Time(activated.RootElement, "created"));
    }

    public async Task CancelRegistrationAsync(RegistrationHandle pending, CancellationToken ct = default)
    {
        if (pending.ProviderReference is not { } factorId)
        {
            return;
        }

        try
        {
            using var _ = await http.DeleteAsync(
                new Uri($"{FactorsUrl(pending.User.Id)}/{Uri.EscapeDataString(factorId)}"), ct);
        }
        catch (PasskeyDirectoryException e) when (e.Status == 404)
        {
            // Already gone: somebody removed it in the admin console, or a retry got here first.
        }
    }

    public async Task<IReadOnlyList<ProviderPasskey>> ListAsync(PasskeyUser user, CancellationToken ct = default)
    {
        using var list = await http.GetAsync(FactorsUrl(user.Id), ct);

        if (list is not { RootElement.ValueKind: JsonValueKind.Array })
        {
            return [];
        }

        return list.RootElement.EnumerateArray()
            .Where(f => Json.Text(f, "factorType") == "webauthn")
            .Select(f => new ProviderPasskey(
                MethodId: Json.Text(f, "id") ?? "",
                DisplayName: Json.Child(f, "profile") is { } p ? Json.Text(p, "authenticatorName") ?? "" : "",
                Created: Json.Time(f, "created"),
                Status: Json.Text(f, "status")))
            .ToList();
    }

    public async Task DeleteAsync(PasskeyUser user, string methodId, CancellationToken ct = default)
    {
        using var _ = await http.DeleteAsync(
            new Uri($"{FactorsUrl(user.Id)}/{Uri.EscapeDataString(methodId)}"), ct);
    }

    private async Task TryDeleteAsync(string userId, string factorId)
    {
        try
        {
            using var _ = await http.DeleteAsync(
                new Uri($"{FactorsUrl(userId)}/{Uri.EscapeDataString(factorId)}"), CancellationToken.None);
        }
        catch (PasskeyDirectoryException)
        {
            // The original failure is the one worth reporting.
        }
    }

    /// <summary>
    /// The configured org when it is the rpId or under it, otherwise the rpId's own
    /// origin. Okta usually leaves <c>rp.id</c> out and the two agree; when it does
    /// send one, it is the answer that decides and the configuration that follows,
    /// because an origin outside the rpId is refused by every authenticator.
    /// </summary>
    internal string Origin(string rpId)
    {
        var host = org.Host;

        return host.Equals(rpId, StringComparison.OrdinalIgnoreCase)
            || host.EndsWith("." + rpId, StringComparison.OrdinalIgnoreCase)
            ? org.GetLeftPart(UriPartial.Authority)
            : $"https://{rpId}";
    }

    /// <summary>
    /// Okta sends the user handle as base64url text, and its own sign-in page
    /// decodes it before handing it to the key. Doing the same is what makes a key
    /// enrolled here indistinguishable from one the user enrolled themselves; an id
    /// that is not base64url at all is used as its characters.
    /// </summary>
    internal static byte[] UserHandle(JsonElement id) =>
        id.ValueKind == JsonValueKind.String && WireBinary.TryDecode(id.GetString()!, out var bytes)
            ? bytes
            : id.ValueKind == JsonValueKind.String ? Encoding.UTF8.GetBytes(id.GetString()!) : WireBinary.Read(id);

    private Uri FactorsUrl(string userId) => new(org, $"/api/v1/users/{Uri.EscapeDataString(userId)}/factors");

    private static PasskeyUser ToUser(JsonElement u)
    {
        var profile = Json.Child(u, "profile") ?? default;
        var name = string.Join(' ', new[] { Json.Text(profile, "firstName"), Json.Text(profile, "lastName") }
            .Where(p => !string.IsNullOrEmpty(p)));

        return new PasskeyUser(
            Id: Json.Text(u, "id") ?? throw new PasskeyDirectoryException($"{Label}: a user without an id."),
            Login: Json.Text(profile, "login") ?? "",
            DisplayName: name,
            Email: Json.Text(profile, "email") ?? "");
    }

    private static string? ErrorDetail(JsonElement body)
    {
        var summary = Json.Text(body, "errorSummary");
        var causes = Json.Child(body, "errorCauses") is { ValueKind: JsonValueKind.Array } c
            ? c.EnumerateArray().Select(x => Json.Text(x, "errorSummary")).OfType<string>().ToList()
            : [];

        return summary is not null && causes.Count > 0 ? $"{summary} ({string.Join("; ", causes)})"
            : summary ?? ProviderHttp.GenericDetail(body);
    }
}
