using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace Blinky.Passkeys;

/// <summary>Produces the Authorization header for a provider call.</summary>
public interface IProviderAuthorization
{
    /// <param name="refresh">
    /// The last token was refused. A provider may revoke one early - a consent
    /// withdrawn, a key rotated - and one fresh attempt is worth more than a cache
    /// that insists it is still valid.
    /// </param>
    Task<AuthenticationHeaderValue> GetAsync(bool refresh, CancellationToken ct);
}

/// <summary>A fixed header: Okta's SSWS API token, for a lab.</summary>
public sealed class StaticAuthorization(string scheme, string value) : IProviderAuthorization
{
    public Task<AuthenticationHeaderValue> GetAsync(bool refresh, CancellationToken ct) =>
        Task.FromResult(new AuthenticationHeaderValue(scheme, value));
}

/// <summary>
/// OAuth 2.0 client credentials, as the application and not as anybody signed in.
/// </summary>
/// <remarks>
/// KeyEnroll signs the operator in with PKCE and calls as them. Blinky's API runs
/// in a container with nobody at it, so it calls as itself and keeps the record of
/// which operator asked in its own audit trail - see docs/12 §5 and §6.1.
/// </remarks>
public sealed class ClientCredentialsAuthorization(
    HttpClient http,
    Uri tokenEndpoint,
    string clientId,
    string scope,
    ClientCredential credential,
    TimeProvider? time = null) : IProviderAuthorization
{
    private static readonly TimeSpan Margin = TimeSpan.FromSeconds(60);

    private readonly TimeProvider clock = time ?? TimeProvider.System;
    private readonly SemaphoreSlim gate = new(1, 1);
    private string? token;
    private DateTimeOffset expires;

    public async Task<AuthenticationHeaderValue> GetAsync(bool refresh, CancellationToken ct)
    {
        await gate.WaitAsync(ct);

        try
        {
            if (refresh || token is null || clock.GetUtcNow() >= expires - Margin)
            {
                (token, expires) = await RequestAsync(ct);
            }

            return new AuthenticationHeaderValue("Bearer", token);
        }
        finally
        {
            gate.Release();
        }
    }

    private async Task<(string, DateTimeOffset)> RequestAsync(CancellationToken ct)
    {
        var form = new List<KeyValuePair<string, string>>
        {
            new("grant_type", "client_credentials"),
            new("client_id", clientId),
            new("scope", scope),
        };
        form.AddRange(credential.FormFields(tokenEndpoint, clientId, clock));

        HttpResponseMessage response;

        try
        {
            response = await http.PostAsync(tokenEndpoint, new FormUrlEncodedContent(form), ct);
        }
        catch (HttpRequestException e)
        {
            throw new PasskeyAuthorizationException($"The token endpoint {tokenEndpoint} could not be reached.", e);
        }

        using (response)
        {
            using var body = await ReadAsync(response, ct);
            var root = body?.RootElement;

            if (!response.IsSuccessStatusCode)
            {
                // Only error and error_description: a token response is the one
                // body in this project that must never end up in a message whole.
                var error = Text(root, "error");
                var description = Text(root, "error_description");
                var dpop = $"{error} {description}".Contains("dpop", StringComparison.OrdinalIgnoreCase)
                    ? " The application requires DPoP, which Blinky does not send; turn "
                      + "\"Require Demonstrating Proof of Possession\" off for this service app."
                    : "";

                throw new PasskeyAuthorizationException(
                    $"{tokenEndpoint.Host} refused a token: HTTP {(int)response.StatusCode}"
                    + (error is null ? "" : $" {error}")
                    + (description is null ? "" : $" - {description}") + "." + dpop);
            }

            var accessToken = Text(root, "access_token")
                ?? throw new PasskeyAuthorizationException($"{tokenEndpoint.Host} returned no access token.");
            var lifetime = root?.TryGetProperty("expires_in", out var e) == true && e.TryGetInt32(out var s)
                ? TimeSpan.FromSeconds(s)
                : TimeSpan.FromMinutes(5);

            return (accessToken, clock.GetUtcNow() + lifetime);
        }
    }

    private static async Task<JsonDocument?> ReadAsync(HttpResponseMessage response, CancellationToken ct)
    {
        try
        {
            return await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(ct), cancellationToken: ct);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static string? Text(JsonElement? root, string name) =>
        root is { ValueKind: JsonValueKind.Object } r && r.TryGetProperty(name, out var v)
            && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
}

/// <summary>How the application proves who it is to the token endpoint.</summary>
public abstract class ClientCredential
{
    internal abstract IEnumerable<KeyValuePair<string, string>> FormFields(
        Uri tokenEndpoint, string clientId, TimeProvider time);

    /// <summary>A shared secret. For a lab; a secret in an environment variable is a secret in every backup of it.</summary>
    public static ClientCredential Secret(string secret) => new SecretCredential(secret);

    /// <summary>
    /// Entra's certificate credential: RS256, identified by the certificate's
    /// SHA-1 thumbprint in <c>x5t</c>, which is the form Microsoft documents for
    /// every RSA certificate it accepts.
    /// </summary>
    public static ClientCredential Certificate(X509Certificate2 certificate)
    {
        var key = certificate.GetRSAPrivateKey()
            ?? throw new PasskeyAuthorizationException(
                "The Entra client certificate has no RSA private key. Entra accepts RSA certificates only.");

        var header = new Dictionary<string, object>
        {
            ["alg"] = "RS256",
            ["typ"] = "JWT",
            ["x5t"] = WireBinary.Encode(certificate.GetCertHash()),
        };

        return new AssertionCredential(key, header);
    }

    /// <summary>Okta's <c>private_key_jwt</c>: RS256 for an RSA key, ES256 for P-256.</summary>
    public static ClientCredential PrivateKey(AsymmetricAlgorithm key, string? keyId)
    {
        var alg = key switch
        {
            RSA => "RS256",
            ECDsa { KeySize: 256 } => "ES256",
            ECDsa => throw new PasskeyAuthorizationException("An EC client key must be P-256 to sign ES256."),
            _ => throw new PasskeyAuthorizationException($"A {key.GetType().Name} key cannot sign a client assertion."),
        };

        var header = new Dictionary<string, object> { ["alg"] = alg, ["typ"] = "JWT" };

        if (keyId is { Length: > 0 })
        {
            header["kid"] = keyId;
        }

        return new AssertionCredential(key, header);
    }

    private sealed class SecretCredential(string secret) : ClientCredential
    {
        internal override IEnumerable<KeyValuePair<string, string>> FormFields(
            Uri tokenEndpoint, string clientId, TimeProvider time) =>
            [new("client_secret", secret)];
    }

    /// <summary>RFC 7523: a JWT signed by the application, audience the token endpoint.</summary>
    private sealed class AssertionCredential(AsymmetricAlgorithm key, IReadOnlyDictionary<string, object> header)
        : ClientCredential
    {
        internal override IEnumerable<KeyValuePair<string, string>> FormFields(
            Uri tokenEndpoint, string clientId, TimeProvider time)
        {
            var now = time.GetUtcNow().ToUnixTimeSeconds();
            var claims = new Dictionary<string, object>
            {
                ["aud"] = tokenEndpoint.ToString(),
                ["iss"] = clientId,
                ["sub"] = clientId,
                ["jti"] = Guid.NewGuid().ToString("N"),
                ["iat"] = now,
                ["nbf"] = now,
                ["exp"] = now + 300,
            };

            var signed = $"{Part(header)}.{Part(claims)}";
            var data = Encoding.ASCII.GetBytes(signed);
            var signature = key switch
            {
                RSA rsa => rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
                // IEEE P1363, which is what JWS wants and what .NET produces by default.
                ECDsa ec => ec.SignData(data, HashAlgorithmName.SHA256),
                _ => throw new InvalidOperationException(),
            };

            return
            [
                new("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                new("client_assertion", $"{signed}.{WireBinary.Encode(signature)}"),
            ];
        }

        private static string Part(IReadOnlyDictionary<string, object> values) =>
            WireBinary.Encode(JsonSerializer.SerializeToUtf8Bytes(values));
    }
}
