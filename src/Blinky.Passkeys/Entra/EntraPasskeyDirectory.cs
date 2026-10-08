using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace Blinky.Passkeys.Entra;

/// <summary>Where the Entra tenant is and how Blinky proves it is the registered app.</summary>
/// <param name="ClientCertificatePath">PFX/P12, or PEM holding certificate and key. Preferred over a secret.</param>
/// <param name="Authority">Changed only for a national cloud.</param>
/// <param name="Graph">Changed only for a national cloud.</param>
/// <param name="ChallengeTimeoutMinutes">
/// What Graph is asked for. It is also the job's deadline, so it has to cover a
/// person finding the key and touching it, not only the round trip.
/// </param>
public sealed record EntraOptions(
    string TenantId,
    string ClientId,
    string? ClientCertificatePath = null,
    string? ClientCertificatePassword = null,
    string? ClientSecret = null,
    string Name = "entra",
    string Authority = "https://login.microsoftonline.com",
    string Graph = "https://graph.microsoft.com",
    int ChallengeTimeoutMinutes = 10);

/// <summary>
/// Microsoft Graph's FIDO2 provisioning: <c>/users/{id}/authentication/fido2Methods</c>.
/// </summary>
/// <remarks>
/// <para>
/// v1.0, not beta. Brief 12 was written against the preview; KeyEnroll calls
/// v1.0 for the same four operations, and so does this. What none of it has done
/// yet is run against a tenant - see the gap on 0073 in docs/STATUS.md.
/// </para>
/// <para>
/// Application permissions, admin-consented: <c>UserAuthenticationMethod.ReadWrite.All</c>
/// for the methods and <c>User.Read.All</c> for <see cref="FindUserAsync"/>.
/// </para>
/// </remarks>
public sealed class EntraPasskeyDirectory : IPasskeyDirectory
{
    /// <summary>Graph refuses a longer FIDO2 method name rather than cutting it.</summary>
    public const int MaxDisplayName = 30;

    private const string Label = "Microsoft Entra ID";
    private const string UserFields = "id,displayName,userPrincipalName,mail";

    private readonly EntraOptions options;
    private readonly ProviderHttp http;
    private readonly TimeProvider time;
    private readonly string api;

    public EntraPasskeyDirectory(EntraOptions options, HttpClient client,
        IProviderAuthorization authorization, TimeProvider? time = null)
    {
        this.options = options;
        this.time = time ?? TimeProvider.System;
        api = $"{options.Graph.TrimEnd('/')}/v1.0";
        http = new ProviderHttp(client, authorization, Label, ErrorDetail, this.time);
    }

    /// <summary>The directory with its own client-credentials token, from configuration.</summary>
    public static EntraPasskeyDirectory Create(EntraOptions options, HttpClient client, TimeProvider? time = null)
    {
        var tokenEndpoint = new Uri(
            $"{options.Authority.TrimEnd('/')}/{Uri.EscapeDataString(options.TenantId)}/oauth2/v2.0/token");
        var authorization = new ClientCredentialsAuthorization(client, tokenEndpoint, options.ClientId,
            $"{options.Graph.TrimEnd('/')}/.default", Credential(options), time);

        return new EntraPasskeyDirectory(options, client, authorization, time);
    }

    private static ClientCredential Credential(EntraOptions options)
    {
        // Certificate first when both are set: a lab that added a certificate and
        // forgot to remove the secret should be running on the certificate.
        if (options.ClientCertificatePath is { Length: > 0 } path)
        {
            var certificate = path.EndsWith(".pem", StringComparison.OrdinalIgnoreCase)
                ? X509Certificate2.CreateFromPemFile(path)
                : X509CertificateLoader.LoadPkcs12FromFile(path, options.ClientCertificatePassword);

            return ClientCredential.Certificate(certificate);
        }

        if (options.ClientSecret is { Length: > 0 } secret)
        {
            return ClientCredential.Secret(secret);
        }

        throw new PasskeyAuthorizationException(
            "Entra has neither a client certificate nor a client secret configured.");
    }

    public string Name => options.Name;

    public PasskeyCapabilities Capabilities { get; } = new(
        SupportsRegistration: true,
        PrepareOnly: false,
        PinDeliveryByProvider: false,
        AcceptsDisplayName: true,
        MaxDisplayNameLength: MaxDisplayName);

    public async Task<PasskeyUser?> FindUserAsync(string identifier, CancellationToken ct = default)
    {
        identifier = identifier.Trim();

        try
        {
            // An object id or a UPN. Escaped whole: a guest's UPN carries '#'.
            using var found = await http.GetAsync(
                new Uri($"{api}/users/{Uri.EscapeDataString(identifier)}?$select={UserFields}"), ct);
            return found is null ? null : ToUser(found.RootElement);
        }
        catch (PasskeyDirectoryException e) when (e.Status is 400 or 404)
        {
            // Not an id and not a UPN. A 403 is not caught: a missing User.Read.All
            // is a configuration fault, and reporting it as "no such user" would
            // send somebody looking for a typo.
        }

        var quoted = identifier.Replace("'", "''", StringComparison.Ordinal);
        using var byMail = await http.GetAsync(new Uri(
            $"{api}/users?$select={UserFields}&$filter={Uri.EscapeDataString($"mail eq '{quoted}'")}"), ct);
        var matches = byMail is null ? [] : Values(byMail.RootElement).ToList();

        return matches.Count == 1 ? ToUser(matches[0]) : null;
    }

    public async Task<PendingRegistration> BeginRegistrationAsync(PasskeyUser user, CancellationToken ct = default)
    {
        var minutes = options.ChallengeTimeoutMinutes.ToString(CultureInfo.InvariantCulture);
        using var answer = await http.GetAsync(
            new Uri($"{MethodsUrl(user.Id)}/creationOptions(challengeTimeoutInMinutes={minutes})"), ct)
            ?? throw new PasskeyDirectoryException($"{Label}: creationOptions returned nothing.");

        var root = answer.RootElement;
        var deadline = Json.Time(root, "challengeTimeoutDateTime")
            ?? time.GetUtcNow().AddMinutes(options.ChallengeTimeoutMinutes);

        var normalised = CreationOptionsReader.Read(
            Json.Required(root, "publicKey", Label),
            Label,
            rpIdFallback: null,
            userHandle: WireBinary.Read,
            // The origin a browser on the rpId would report. Taken from the answer
            // so a tenant moved to another sign-in host keeps working.
            origin: rpId => $"https://{rpId}",
            deadline);

        // Entra keeps nothing between the two calls; the challenge just expires.
        return new PendingRegistration(user, normalised, ProviderReference: null);
    }

    public async Task<RegisteredPasskey> CompleteRegistrationAsync(PendingRegistration pending,
        AttestationResponse response, string displayName, CancellationToken ct = default)
    {
        var name = displayName.Trim() is { Length: > 0 } n ? n : "YubiKey";

        var body = new
        {
            displayName = name.Length > MaxDisplayName ? name[..MaxDisplayName] : name,
            publicKeyCredential = new
            {
                id = WireBinary.Encode(response.CredentialId),
                response = new
                {
                    clientDataJSON = WireBinary.Encode(response.ClientDataJson),
                    attestationObject = WireBinary.Encode(response.AttestationObject),
                },
            },
        };

        using var created = await http.PostAsync(new Uri(MethodsUrl(pending.User.Id)), body, ct)
            ?? throw new PasskeyDirectoryException($"{Label}: the registration returned no method.");

        return new RegisteredPasskey(
            Json.Text(created.RootElement, "id")
                ?? throw new PasskeyDirectoryException($"{Label}: the registered method has no id."),
            Json.Time(created.RootElement, "createdDateTime"));
    }

    public Task CancelRegistrationAsync(PendingRegistration pending, CancellationToken ct = default) =>
        Task.CompletedTask;

    public async Task<IReadOnlyList<ProviderPasskey>> ListAsync(PasskeyUser user, CancellationToken ct = default)
    {
        using var list = await http.GetAsync(new Uri(MethodsUrl(user.Id)), ct);

        return list is null ? [] : Values(list.RootElement).Select(m => new ProviderPasskey(
            MethodId: Json.Text(m, "id") ?? "",
            DisplayName: Json.Text(m, "displayName") ?? "",
            Created: Json.Time(m, "createdDateTime"),
            Aaguid: Guid.TryParse(Json.Text(m, "aaGuid"), out var g) ? g : null,
            Model: Json.Text(m, "model"))).ToList();
    }

    public async Task DeleteAsync(PasskeyUser user, string methodId, CancellationToken ct = default)
    {
        using var _ = await http.DeleteAsync(
            new Uri($"{MethodsUrl(user.Id)}/{Uri.EscapeDataString(methodId)}"), ct);
    }

    private string MethodsUrl(string userId) =>
        $"{api}/users/{Uri.EscapeDataString(userId)}/authentication/fido2Methods";

    private static IEnumerable<JsonElement> Values(JsonElement root) =>
        Json.Child(root, "value") is { ValueKind: JsonValueKind.Array } v ? v.EnumerateArray() : [];

    private static PasskeyUser ToUser(JsonElement u) => new(
        Id: Json.Text(u, "id") ?? throw new PasskeyDirectoryException($"{Label}: a user without an id."),
        Login: Json.Text(u, "userPrincipalName") ?? "",
        DisplayName: Json.Text(u, "displayName") ?? "",
        Email: Json.Text(u, "mail") ?? "");

    private static string? ErrorDetail(JsonElement body) =>
        Json.Child(body, "error") is { ValueKind: JsonValueKind.Object } error
            ? Json.Text(error, "message") ?? Json.Text(error, "code")
            : ProviderHttp.GenericDetail(body);
}
