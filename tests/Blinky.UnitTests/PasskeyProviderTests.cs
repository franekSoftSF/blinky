using System.Buffers.Text;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Blinky.Api.Passkeys;
using Blinky.Domain;
using Blinky.Domain.Entities;
using Blinky.Secrets;
using Microsoft.Extensions.Logging.Abstractions;

namespace Blinky.UnitTests;

/// <summary>
/// 0107: passkey providers in the database, configured in the console, with the
/// credential sealed and never handed back.
/// </summary>
public sealed class PasskeyProviderTests : IDisposable
{
    private static readonly DateTime Now = new(2026, 10, 9, 10, 0, 0, DateTimeKind.Utc);

    private readonly ConfigurationKeyProvider keys = new(new Dictionary<KeyRef, byte[]>
    {
        [new KeyRef(KeyPurpose.PukKek, 2)] = RandomNumberGenerator.GetBytes(32),
    });

    private readonly MemoryProviders store = new();
    private readonly PasskeyProviders providers;

    public PasskeyProviderTests() =>
        providers = new PasskeyProviders(store, new ProviderSecrets(keys, 2),
            NullLogger<PasskeyProviders>.Instance, new FakeTime(new DateTimeOffset(Now)));

    public void Dispose() => keys.Dispose();

    private static PasskeyProviderRequest Entra(string name = "entra") =>
        new(name, PasskeyProviderKind.Entra, TenantId: "contoso.onmicrosoft.com",
            ClientId: "0b1f6d4e-4a4c-4a2b-9f5e-6a3c2d1e0f9a");

    private static PasskeyProviderRequest Okta(string name = "okta") =>
        new(name, PasskeyProviderKind.Okta, OrgUrl: "acme.okta.com", ClientId: "0oa1");

    [Fact]
    public void A_sealed_credential_opens_on_its_own_row_and_on_no_other()
    {
        var secrets = new ProviderSecrets(keys, 2);
        var row = Row(Guid.NewGuid());
        var other = Row(Guid.NewGuid());

        secrets.Seal(row, PasskeyProviderCredential.ClientSecret, "s3cr3t");

        Assert.Equal("s3cr3t", secrets.Open(row));
        Assert.DoesNotContain("s3cr3t"u8.ToArray(), row.SecretCiphertext!.Chunk(6).Select(c => c.ToArray()), new BytesEquality());

        // Copied to another provider's row: the id is authenticated.
        other.CredentialKind = row.CredentialKind;
        other.SecretCiphertext = row.SecretCiphertext;
        other.SecretNonce = row.SecretNonce;
        other.SecretTag = row.SecretTag;
        other.SecretKeyVersion = row.SecretKeyVersion;
        Assert.ThrowsAny<CryptographicException>(() => secrets.Open(other));

        // Relabelled as another kind of credential: so is the kind.
        row.CredentialKind = PasskeyProviderCredential.Certificate;
        Assert.ThrowsAny<CryptographicException>(() => secrets.Open(row));
    }

    [Fact]
    public void A_generated_entra_credential_is_a_certificate_whose_key_never_leaves()
    {
        var created = providers.Create(Entra(), "admin");

        var view = providers.GenerateCredential(created.Id, "admin");

        Assert.Equal(PasskeyProviderCredential.Certificate, view.CredentialKind);
        Assert.True(view.CredentialSet);
        using var certificate = X509Certificate2.CreateFromPem(view.PublicMaterial!);
        Assert.False(certificate.HasPrivateKey);
        Assert.Equal(certificate.Thumbprint, view.CredentialHint);
        Assert.Equal(Now.AddYears(2), view.CredentialExpiresAt!.Value, TimeSpan.FromMinutes(10));
        Assert.DoesNotContain("PRIVATE KEY", JsonSerializer.Serialize(view));
    }

    [Fact]
    public void A_generated_okta_credential_is_a_jwk_with_an_rfc_7638_kid()
    {
        var created = providers.Create(Okta(), "admin");

        var view = providers.GenerateCredential(created.Id, "admin");

        using var jwk = JsonDocument.Parse(view.PublicMaterial!);
        var root = jwk.RootElement;
        var canonical = $"{{\"e\":\"{root.GetProperty("e").GetString()}\",\"kty\":\"RSA\",\"n\":\"{root.GetProperty("n").GetString()}\"}}";
        var expected = Base64Url.EncodeToString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));

        Assert.Equal(expected, root.GetProperty("kid").GetString());
        Assert.Equal(expected, view.KeyId);
        Assert.False(root.TryGetProperty("d", out _));
        Assert.False(root.TryGetProperty("p", out _));
    }

    [Fact]
    public void An_imported_pfx_is_stored_as_pem_and_its_password_is_not_kept()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = new CertificateRequest("CN=imported", rsa, HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        var pfx = Convert.ToBase64String(certificate.Export(X509ContentType.Pfx, "hunter2"));
        var created = providers.Create(Entra(), "admin");

        var view = providers.ImportCredential(created.Id,
            new PasskeyCredentialImport(PasskeyProviderCredential.Certificate, pfx, "hunter2"), "admin");

        Assert.Equal(certificate.Thumbprint, view.CredentialHint);
        var sealedText = new ProviderSecrets(keys, 2).Open(store.Rows.Single());
        Assert.Contains("BEGIN PRIVATE KEY", sealedText);
        Assert.DoesNotContain("hunter2", sealedText);
        Assert.DoesNotContain(store.Audit, a => a.Detail.Contains("hunter2") || a.Detail.Contains("PRIVATE"));
    }

    [Fact]
    public void An_entra_client_secret_keeps_its_portal_id_and_expiry_but_not_its_value()
    {
        var created = providers.Create(Entra(), "admin");
        var expires = new DateTime(2027, 4, 1, 0, 0, 0, DateTimeKind.Utc);

        var view = providers.ImportCredential(created.Id, new PasskeyCredentialImport(
            PasskeyProviderCredential.ClientSecret, "Q~abc.secret-value", Label: "8f1c2d3e-secret-id", ExpiresAt: expires),
            "admin");

        Assert.Equal("8f1c2d3e-secret-id", view.CredentialHint);
        Assert.Equal(expires, view.CredentialExpiresAt);
        Assert.DoesNotContain("Q~abc", JsonSerializer.Serialize(view));
        Assert.Equal("Q~abc.secret-value", new ProviderSecrets(keys, 2).Open(store.Rows.Single()));
        Assert.Equal("entra", Assert.Single(providers.Directories.All).Name);
    }

    [Fact]
    public void A_credential_the_provider_would_refuse_is_refused_on_save()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var certificate = new CertificateRequest("CN=ec", ec, HashAlgorithmName.SHA256)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        var pem = certificate.ExportCertificatePem() + "\n" + ec.ExportPkcs8PrivateKeyPem();
        var entra = providers.Create(Entra(), "admin");
        var okta = providers.Create(Okta(), "admin");

        Assert.Equal("bad-credential", Assert.Throws<PasskeyFlowException>(() => providers.ImportCredential(entra.Id,
            new PasskeyCredentialImport(PasskeyProviderCredential.Certificate, pem), "admin")).Code);

        // An Okta key in an Entra slot, and the other way round.
        Assert.Equal("bad-credential", Assert.Throws<PasskeyFlowException>(() => providers.ImportCredential(okta.Id,
            new PasskeyCredentialImport(PasskeyProviderCredential.ClientSecret, "x"), "admin")).Code);
        Assert.False(store.Rows.Single(r => r.Id == okta.Id).SecretCiphertext is not null);
    }

    [Theory]
    [InlineData("Entra Prod", "bad-name")]
    [InlineData("", "bad-name")]
    [InlineData("entra", "name-taken")]
    public void A_name_is_simple_and_unique(string name, string code)
    {
        providers.Create(Entra(), "admin");

        Assert.Equal(code, Assert.Throws<PasskeyFlowException>(() => providers.Create(Entra(name), "admin")).Code);
    }

    [Fact]
    public void Settings_the_provider_would_refuse_are_refused_here()
    {
        Assert.Equal("bad-entra", Assert.Throws<PasskeyFlowException>(() =>
            providers.Create(Entra() with { ClientId = "not-a-guid" }, "admin")).Code);
        Assert.Equal("bad-okta", Assert.Throws<PasskeyFlowException>(() =>
            providers.Create(Okta() with { OrgUrl = "http://acme.okta.com" }, "admin")).Code);
        Assert.Equal("bad-challenge", Assert.Throws<PasskeyFlowException>(() =>
            providers.Create(Entra() with { ChallengeMinutes = 2 }, "admin")).Code);
    }

    [Fact]
    public void The_kind_is_fixed_once_created()
    {
        var created = providers.Create(Entra(), "admin");

        Assert.Equal("kind-fixed", Assert.Throws<PasskeyFlowException>(() =>
            providers.Update(created.Id, Okta("entra"), "admin")).Code);
    }

    [Fact]
    public void A_provider_with_registered_passkeys_is_disabled_not_deleted()
    {
        var created = providers.Create(Okta(), "admin");
        store.InUse.Add("okta");

        Assert.Equal("in-use", Assert.Throws<PasskeyFlowException>(() => providers.Delete(created.Id, "admin")).Code);

        providers.Update(created.Id, Okta() with { IsEnabled = false }, "admin");
        Assert.False(store.Rows.Single().IsEnabled);
    }

    [Fact]
    public void The_registry_follows_the_database_and_shows_why_a_provider_is_missing()
    {
        var created = providers.Create(Okta(), "admin");

        Assert.Empty(providers.Directories.All);
        Assert.Contains("No credential", providers.List().Single().Problem);

        providers.GenerateCredential(created.Id, "admin");
        Assert.Equal("okta", Assert.Single(providers.Directories.All).Name);
        Assert.Null(providers.List().Single().Problem);

        providers.Update(created.Id, Okta() with { IsEnabled = false }, "admin");
        Assert.Empty(providers.Directories.All);
    }

    [Fact]
    public void Kinds_and_drift_cross_the_wire_as_words()
    {
        // The console compares "Entra" and "InSync". As numbers, a create from the
        // console was a 400 with no body and every drift read as none - found by
        // running it against a real API, which no stand-in would have shown.
        var web = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        var view = providers.Create(Entra(), "admin");

        Assert.Contains("\"kind\":\"Entra\"", JsonSerializer.Serialize(view, web));
        Assert.Contains("\"MissingAtProvider\"", JsonSerializer.Serialize(
            new PasskeyListing(null, "m", "n", "Registered", null, null, null, PasskeyDrift.MissingAtProvider, null), web));
        Assert.Equal(PasskeyProviderKind.Okta,
            JsonSerializer.Deserialize<PasskeyProviderRequest>("{\"name\":\"o\",\"kind\":\"Okta\"}", web)!.Kind);
    }

    [Fact]
    public void Nothing_the_console_is_sent_can_hold_the_credential()
    {
        var offenders = typeof(PasskeyProviderView).GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => p.Name.Contains("Secret", StringComparison.OrdinalIgnoreCase)
                        || p.Name.Contains("Password", StringComparison.OrdinalIgnoreCase)
                        || p.Name.Contains("Token", StringComparison.OrdinalIgnoreCase))
            .Select(p => p.Name)
            .ToList();

        Assert.Empty(offenders);
    }

    private static PasskeyProvider Row(Guid id)
    {
        var row = new PasskeyProvider { Name = "x", Kind = PasskeyProviderKind.Entra };
        typeof(PasskeyProvider).GetProperty("Id")!.SetValue(row, id);
        return row;
    }

    private sealed class BytesEquality : IEqualityComparer<byte[]>
    {
        public bool Equals(byte[]? x, byte[]? y) => x is not null && y is not null && x.SequenceEqual(y);

        public int GetHashCode(byte[] obj) => obj.Length;
    }

    private sealed class MemoryProviders : IPasskeyProviderStore
    {
        public List<PasskeyProvider> Rows { get; } = [];

        public List<AuditEvent> Audit { get; } = [];

        public HashSet<string> InUse { get; } = [];

        public IReadOnlyList<PasskeyProvider> All() => Rows.OrderBy(r => r.Name).ToList();

        public PasskeyProvider? Get(Guid id) => Rows.SingleOrDefault(r => r.Id == id);

        public bool NameTaken(string name) => Rows.Any(r => r.Name == name);

        public bool HasRegisteredPasskeys(string name) => InUse.Contains(name);

        public void Save(PasskeyProvider row, AuditEvent audit)
        {
            if (row.Id == Guid.Empty)
            {
                typeof(PasskeyProvider).GetProperty("Id")!.SetValue(row, Guid.NewGuid());
            }

            if (!Rows.Contains(row))
            {
                Rows.Add(row);
            }

            audit.SubjectId ??= row.Id;
            Audit.Add(audit);
        }

        public void Delete(PasskeyProvider row, AuditEvent audit)
        {
            Rows.Remove(row);
            Audit.Add(audit);
        }
    }
}
