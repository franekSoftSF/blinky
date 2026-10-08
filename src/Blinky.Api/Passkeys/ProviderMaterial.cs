using System.Buffers.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Blinky.Domain.Entities;
using Blinky.Passkeys;

namespace Blinky.Api.Passkeys;

/// <summary>A credential ready to seal, with what may be shown about it.</summary>
/// <param name="Secret">What goes into the envelope and nowhere else.</param>
/// <param name="PublicMaterial">For the administrator to give the provider; null for a shared secret.</param>
/// <param name="Hint">What identifies it in the console: a thumbprint, a key id.</param>
/// <param name="KeyId">Okta's <c>kid</c>, when Blinky worked it out.</param>
public sealed record PreparedCredential(
    PasskeyProviderCredential Kind,
    string Secret,
    string? PublicMaterial,
    string Hint,
    DateTime? ExpiresAt,
    string? KeyId = null);

/// <summary>
/// Makes, imports and opens the credentials a provider is reached with.
/// </summary>
/// <remarks>
/// Generating is the route the console offers first, and the reason is where the
/// private key ends up: made here, sealed here, never in a browser, a download
/// folder or a ticket. The administrator gives the provider the public half - a
/// certificate for Entra, a JWK for Okta - which is all either of them needs.
/// </remarks>
public static class ProviderMaterial
{
    public static PreparedCredential Generate(PasskeyProviderKind kind, string providerName, DateTime nowUtc) =>
        kind switch
        {
            PasskeyProviderKind.Entra => GenerateCertificate(providerName, nowUtc),
            PasskeyProviderKind.Okta => GeneratePrivateKey(),
            _ => throw new ArgumentOutOfRangeException(nameof(kind)),
        };

    /// <summary>
    /// A credential the administrator brought. Refused here if it would be refused
    /// by the provider, so the console says so on save and not on the first ceremony.
    /// </summary>
    /// <param name="value">PEM for a certificate or key, base64 PFX for a certificate, or the secret itself.</param>
    public static PreparedCredential Import(PasskeyProviderKind provider, PasskeyProviderCredential kind,
        string value, string? password)
    {
        Allowed(provider, kind);
        value = value.Trim();

        if (value.Length == 0)
        {
            throw new ArgumentException("The credential is empty.");
        }

        switch (kind)
        {
            case PasskeyProviderCredential.Certificate:
            {
                using var certificate = value.Contains("-----BEGIN", StringComparison.Ordinal)
                    ? X509Certificate2.CreateFromPem(value)
                    : X509CertificateLoader.LoadPkcs12(Convert.FromBase64String(value), password,
                        X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);

                using var rsa = certificate.GetRSAPrivateKey()
                                ?? throw new ArgumentException(
                                    "The certificate has no RSA private key with it. Entra accepts RSA certificates only.");

                return Certificate(certificate, rsa);
            }

            case PasskeyProviderCredential.PrivateKey:
            {
                using var key = Key(value);
                return PrivateKey(key);
            }

            default:
                // A shared secret has nothing to show but that it is there.
                return new PreparedCredential(kind, value, null, "set", null);
        }
    }

    /// <summary>Which credentials a provider can be given.</summary>
    public static void Allowed(PasskeyProviderKind provider, PasskeyProviderCredential kind)
    {
        var ok = provider switch
        {
            PasskeyProviderKind.Entra => kind is PasskeyProviderCredential.Certificate or PasskeyProviderCredential.ClientSecret,
            PasskeyProviderKind.Okta => kind is PasskeyProviderCredential.PrivateKey or PasskeyProviderCredential.ApiToken,
            _ => false,
        };

        if (!ok)
        {
            throw new ArgumentException($"{provider} is not reached with a {kind}.");
        }
    }

    /// <summary>The Entra credential, from what the envelope held.</summary>
    public static ClientCredential EntraCredential(PasskeyProviderCredential kind, string secret) => kind switch
    {
        PasskeyProviderCredential.Certificate => ClientCredential.Certificate(CertificateFromPem(secret)),
        PasskeyProviderCredential.ClientSecret => ClientCredential.Secret(secret),
        _ => throw new ArgumentException($"Entra is not reached with a {kind}."),
    };

    public static AsymmetricAlgorithm Key(string pem)
    {
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

            try
            {
                ec.ImportFromPem(pem);
            }
            catch (Exception inner) when (inner is CryptographicException or ArgumentException)
            {
                ec.Dispose();
                throw new ArgumentException("That is neither an RSA nor an EC private key in PEM.", inner);
            }

            if (ec.KeySize != 256)
            {
                ec.Dispose();
                throw new ArgumentException("An EC key for Okta has to be P-256.");
            }

            return ec;
        }
    }

    private static X509Certificate2 CertificateFromPem(string pem)
    {
        // Both halves in one string, as Import and Generate wrote them.
        var keyStart = pem.IndexOf("-----BEGIN PRIVATE KEY-----", StringComparison.Ordinal);
        return X509Certificate2.CreateFromPem(pem.AsSpan(0, keyStart), pem.AsSpan(keyStart));
    }

    private static PreparedCredential GenerateCertificate(string providerName, DateTime nowUtc)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest($"CN=Blinky passkeys ({providerName})", rsa,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Two years: long enough not to be a monthly chore, short enough that a key
        // nobody looks after stops working before it is forgotten entirely.
        using var certificate = request.CreateSelfSigned(nowUtc.AddMinutes(-5), nowUtc.AddYears(2));

        return Certificate(certificate, rsa);
    }

    private static PreparedCredential Certificate(X509Certificate2 certificate, RSA rsa)
    {
        var certificatePem = certificate.ExportCertificatePem();

        return new PreparedCredential(
            PasskeyProviderCredential.Certificate,
            certificatePem + "\n" + rsa.ExportPkcs8PrivateKeyPem(),
            certificatePem,
            // SHA-1, because that is the thumbprint Entra's portal lists the
            // certificate under, and the point of the hint is to match it there.
            certificate.Thumbprint,
            certificate.NotAfter.ToUniversalTime());
    }

    private static PreparedCredential GeneratePrivateKey()
    {
        using var rsa = RSA.Create(2048);
        return PrivateKey(rsa);
    }

    private static PreparedCredential PrivateKey(AsymmetricAlgorithm key)
    {
        var (jwk, kid) = Jwk(key);
        var pem = key switch
        {
            RSA rsa => rsa.ExportPkcs8PrivateKeyPem(),
            ECDsa ec => ec.ExportPkcs8PrivateKeyPem(),
            _ => throw new ArgumentException("Unsupported key."),
        };

        return new PreparedCredential(PasskeyProviderCredential.PrivateKey, pem, jwk, kid, null, kid);
    }

    /// <summary>The public JWK Okta asks for, with an RFC 7638 thumbprint as its kid.</summary>
    private static (string Jwk, string Kid) Jwk(AsymmetricAlgorithm key)
    {
        string B(byte[] bytes) => Base64Url.EncodeToString(bytes);

        // The thumbprint input is the required members only, in lexicographic
        // order, with no whitespace - RFC 7638 §3.
        (string canonical, Dictionary<string, string> members) = key switch
        {
            RSA rsa when rsa.ExportParameters(false) is var p =>
                ($"{{\"e\":\"{B(p.Exponent!)}\",\"kty\":\"RSA\",\"n\":\"{B(p.Modulus!)}\"}}",
                    new Dictionary<string, string> { ["kty"] = "RSA", ["e"] = B(p.Exponent!), ["n"] = B(p.Modulus!), ["alg"] = "RS256" }),
            ECDsa ec when ec.ExportParameters(false) is var p =>
                ($"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{B(p.Q.X!)}\",\"y\":\"{B(p.Q.Y!)}\"}}",
                    new Dictionary<string, string> { ["kty"] = "EC", ["crv"] = "P-256", ["x"] = B(p.Q.X!), ["y"] = B(p.Q.Y!), ["alg"] = "ES256" }),
            _ => throw new ArgumentException("Unsupported key."),
        };

        var kid = B(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(canonical)));
        members["kid"] = kid;
        members["use"] = "sig";

        return (JsonSerializer.Serialize(members, new JsonSerializerOptions { WriteIndented = true }), kid);
    }
}
