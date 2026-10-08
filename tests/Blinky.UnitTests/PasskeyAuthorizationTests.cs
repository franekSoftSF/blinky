using System.Buffers.Text;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Blinky.Contracts;
using Blinky.Passkeys;
using Blinky.Passkeys.Okta;

namespace Blinky.UnitTests;

/// <summary>
/// How Blinky proves to Entra and Okta that it is the registered application,
/// and the small pieces both directories share.
/// </summary>
public sealed class PasskeyAuthorizationTests
{
    private static readonly Uri TokenEndpoint = new("https://acme.okta.com/oauth2/v1/token");
    private static readonly DateTimeOffset Now = new(2026, 10, 8, 10, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task A_private_key_jwt_is_signed_for_the_token_endpoint_and_nothing_else()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var provider = new FakeProvider().Answer(new { access_token = "AT", token_type = "Bearer", expires_in = 3600 });
        var authorization = new ClientCredentialsAuthorization(provider.Client, TokenEndpoint, "CLIENT",
            "okta.users.read okta.users.manage", ClientCredential.PrivateKey(key, "kid-1"), new FakeTime(Now));

        var header = await authorization.GetAsync(false, default);

        Assert.Equal("Bearer AT", header.ToString());
        var form = provider.Calls[0].Form;
        Assert.Equal("client_credentials", form["grant_type"]);
        Assert.Equal("okta.users.read okta.users.manage", form["scope"]);
        Assert.Equal("urn:ietf:params:oauth:client-assertion-type:jwt-bearer", form["client_assertion_type"]);
        Assert.False(form.ContainsKey("client_secret"));

        var (jwtHeader, claims, signed, signature) = Split(form["client_assertion"]);
        Assert.Equal("ES256", jwtHeader.GetProperty("alg").GetString());
        Assert.Equal("kid-1", jwtHeader.GetProperty("kid").GetString());
        Assert.Equal(TokenEndpoint.ToString(), claims.GetProperty("aud").GetString());
        Assert.Equal("CLIENT", claims.GetProperty("iss").GetString());
        Assert.Equal("CLIENT", claims.GetProperty("sub").GetString());
        Assert.Equal(Now.ToUnixTimeSeconds() + 300, claims.GetProperty("exp").GetInt64());
        Assert.True(key.VerifyData(signed, signature, HashAlgorithmName.SHA256));
    }

    [Fact]
    public async Task An_entra_certificate_assertion_names_the_certificate_by_thumbprint()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = new CertificateRequest("CN=blinky-entra", rsa, HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1).CreateSelfSigned(Now.AddDays(-1), Now.AddDays(30));
        var provider = new FakeProvider().Answer(new { access_token = "AT", expires_in = 3600 });
        var authorization = new ClientCredentialsAuthorization(provider.Client,
            new Uri("https://login.microsoftonline.com/TENANT/oauth2/v2.0/token"), "CLIENT",
            "https://graph.microsoft.com/.default", ClientCredential.Certificate(certificate), new FakeTime(Now));

        await authorization.GetAsync(false, default);

        var (jwtHeader, _, signed, signature) = Split(provider.Calls[0].Form["client_assertion"]);
        Assert.Equal("RS256", jwtHeader.GetProperty("alg").GetString());
        Assert.Equal(Base64Url.EncodeToString(certificate.GetCertHash()), jwtHeader.GetProperty("x5t").GetString());
        Assert.True(rsa.VerifyData(signed, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        Assert.Equal("https://graph.microsoft.com/.default", provider.Calls[0].Form["scope"]);
    }

    [Fact]
    public void A_certificate_without_an_rsa_key_is_refused_before_entra_refuses_it()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var certificate = new CertificateRequest("CN=x", ec, HashAlgorithmName.SHA256)
            .CreateSelfSigned(Now.AddDays(-1), Now.AddDays(1));

        Assert.Throws<PasskeyAuthorizationException>(() => ClientCredential.Certificate(certificate));
    }

    [Fact]
    public async Task A_token_is_reused_until_a_minute_before_it_expires_or_until_it_is_refused()
    {
        var time = new FakeTime(Now);
        var provider = new FakeProvider()
            .Answer(new { access_token = "ONE", expires_in = 600 })
            .Answer(new { access_token = "TWO", expires_in = 600 })
            .Answer(new { access_token = "THREE", expires_in = 600 });
        var authorization = new ClientCredentialsAuthorization(provider.Client, TokenEndpoint, "CLIENT", "s",
            ClientCredential.Secret("SECRET"), time);

        Assert.Equal("Bearer ONE", (await authorization.GetAsync(false, default)).ToString());
        time.Now = Now.AddMinutes(8);
        Assert.Equal("Bearer ONE", (await authorization.GetAsync(false, default)).ToString());
        time.Now = Now.AddMinutes(9);
        Assert.Equal("Bearer TWO", (await authorization.GetAsync(false, default)).ToString());
        Assert.Equal("Bearer THREE", (await authorization.GetAsync(true, default)).ToString());
        Assert.Equal("SECRET", provider.Calls[0].Form["client_secret"]);
    }

    [Fact]
    public async Task A_refused_token_says_why_without_repeating_the_body()
    {
        var provider = new FakeProvider().Answer(
            new { error = "invalid_dpop_proof", error_description = "The DPoP proof JWT header is missing.", trace = "SECRET-ish" },
            HttpStatusCode.BadRequest);
        var authorization = new ClientCredentialsAuthorization(provider.Client, TokenEndpoint, "CLIENT", "s",
            ClientCredential.Secret("x"), new FakeTime(Now));

        var e = await Assert.ThrowsAsync<PasskeyAuthorizationException>(() => authorization.GetAsync(false, default));

        Assert.Contains("invalid_dpop_proof", e.Message);
        Assert.Contains("Require Demonstrating Proof of Possession", e.Message);
        Assert.DoesNotContain("SECRET-ish", e.Message);
    }

    [Fact]
    public void Okta_refuses_to_start_without_the_credential_its_mode_needs()
    {
        Assert.Throws<PasskeyAuthorizationException>(() =>
            OktaPasskeyDirectory.Create(new OktaOptions("acme.okta.com", OktaAuthMode.ApiToken), new HttpClient()));
        Assert.Throws<PasskeyAuthorizationException>(() =>
            OktaPasskeyDirectory.Create(new OktaOptions("acme.okta.com", ClientId: "C"), new HttpClient()));
    }

    [Theory]
    [InlineData("AQID")]
    [InlineData("AQID==")]
    [InlineData("AQI=")]
    public void Binary_text_is_read_in_any_base64_spelling(string text) =>
        Assert.Equal([1, 2], WireBinary.Decode(text)[..2]);

    [Fact]
    public void Standard_and_url_alphabets_mean_the_same_bytes() =>
        Assert.Equal(WireBinary.Decode("-__-AQ"), WireBinary.Decode("+//+AQ=="));

    [Fact]
    public void A_signed_byte_array_reads_as_the_bytes_it_was()
    {
        using var doc = JsonDocument.Parse("[-6, -5, 1, 255]");

        Assert.Equal([0xFA, 0xFB, 0x01, 0xFF], WireBinary.Read(doc.RootElement));
    }

    [Theory]
    [InlineData("YubiKey 5C NFC", 12345678L, 30, "YubiKey 5C NFC 12345678")]
    [InlineData("A name that is far longer than thirty", 12345678L, 30, "A name that is far lo 12345678")]
    [InlineData("", 12345678L, 30, "YubiKey 12345678")]
    [InlineData("  Key  ", null, null, "Key")]
    [InlineData("A name that is far longer than thirty", null, 30, "A name that is far longer than")]
    public void The_serial_survives_a_length_limit(string baseName, long? serial, int? limit, string expected) =>
        Assert.Equal(expected, Fido2KeyName.Compose(baseName, serial, limit));

    private static (JsonElement Header, JsonElement Claims, byte[] Signed, byte[] Signature) Split(string jwt)
    {
        var parts = jwt.Split('.');
        Assert.Equal(3, parts.Length);

        return (
            JsonDocument.Parse(Base64Url.DecodeFromChars(parts[0])).RootElement,
            JsonDocument.Parse(Base64Url.DecodeFromChars(parts[1])).RootElement,
            Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}"),
            Base64Url.DecodeFromChars(parts[2]));
    }
}
