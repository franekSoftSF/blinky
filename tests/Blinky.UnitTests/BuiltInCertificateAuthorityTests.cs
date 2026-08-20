using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Blinky.Domain;
using Blinky.Pki;
using Blinky.Pki.BuiltIn;

namespace Blinky.UnitTests;

/// <summary>
/// The built-in CA, in both shapes. Everything here is checkable without a
/// domain: whether the chain validates, and whether the certificate contains
/// what a domain controller will look for. Whether it then <i>works</i> is the
/// Phase 2 gate and needs the lab — but a certificate that is wrong here will
/// never work there, and this is where that is cheap to find out.
/// </summary>
public sealed class BuiltInCertificateAuthorityTests
{
    private const string ClientAuthOid = "1.3.6.1.5.5.7.3.2";

    [Theory]
    [InlineData(CaTopology.Single)]
    [InlineData(CaTopology.TwoTier)]
    public async Task An_issued_certificate_chains_to_the_anchor(CaTopology topology)
    {
        using var ca = Authority(topology);
        var issued = await ca.IssueAsync(Request());

        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(ca.TrustAnchor);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

        foreach (var link in issued.Chain)
        {
            chain.ChainPolicy.ExtraStore.Add(link);
        }

        Assert.True(chain.Build(issued.Certificate),
            string.Join("; ", chain.ChainStatus.Select(s => s.StatusInformation.Trim())));
    }

    [Fact]
    public void Single_is_its_own_anchor_and_two_tier_is_not()
    {
        using var single = Authority(CaTopology.Single);
        using var twoTier = Authority(CaTopology.TwoTier);

        Assert.Equal(single.TrustAnchor.Thumbprint, single.Issuer.Thumbprint);
        Assert.NotEqual(twoTier.TrustAnchor.Thumbprint, twoTier.Issuer.Thumbprint);
    }

    [Theory]
    [InlineData(CaTopology.Single, 0)]
    [InlineData(CaTopology.TwoTier, 1)]
    public void The_anchor_allows_exactly_as_many_intermediates_as_the_topology_has(
        CaTopology topology, int expected)
    {
        // pathLenConstraint counts what may follow. A two-tier root has one
        // intermediate after it; a single CA has none. Reversed, every chain
        // through the issuing CA is rejected with "basic constraints not
        // satisfied", which points at the leaf and not at the root.
        using var ca = Authority(topology);

        var constraints = ca.TrustAnchor.Extensions
            .OfType<X509BasicConstraintsExtension>()
            .Single();

        Assert.True(constraints.CertificateAuthority);
        Assert.True(constraints.HasPathLengthConstraint);
        Assert.Equal(expected, constraints.PathLengthConstraint);
    }

    [Fact]
    public void A_two_tier_issuer_may_sign_no_further_authorities()
    {
        using var ca = Authority(CaTopology.TwoTier);

        var constraints = ca.Issuer.Extensions
            .OfType<X509BasicConstraintsExtension>()
            .Single();

        Assert.Equal(0, constraints.PathLengthConstraint);
    }

    [Fact]
    public async Task The_subject_comes_from_the_cardholder_not_from_the_request()
    {
        // A token proves it holds a key. It does not get to choose whose
        // certificate that key ends up in.
        using var ca = Authority(CaTopology.TwoTier);
        var issued = await ca.IssueAsync(Request(requestSubject: "CN=Administrator"));

        Assert.Equal("CN=Jan Kowalski", issued.Certificate.Subject);
    }

    [Fact]
    public async Task The_sid_extension_is_present_and_carries_the_sid()
    {
        // The single most common reason a self-built PKI fails at smart-card
        // logon, and it fails silently: the certificate looks perfect.
        using var ca = Authority(CaTopology.TwoTier);
        var issued = await ca.IssueAsync(Request());

        var extension = issued.Certificate.Extensions
            .Single(e => e.Oid?.Value == BuiltInCertificateAuthority.SidExtensionOid);

        Assert.Contains("S-1-5-21-1-2-3-1104", DecodeOtherNameString(extension.RawData),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_upn_is_in_the_subject_alternative_name()
    {
        using var ca = Authority(CaTopology.TwoTier);
        var issued = await ca.IssueAsync(Request());

        var san = issued.Certificate.Extensions.Single(e => e.Oid?.Value == "2.5.29.17");

        Assert.Contains("jkowalski@corp.example", DecodeOtherNameString(san.RawData),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task Both_logon_extended_key_usages_are_present()
    {
        using var ca = Authority(CaTopology.TwoTier);
        var issued = await ca.IssueAsync(Request());

        var eku = issued.Certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single();
        var oids = eku.EnhancedKeyUsages.Cast<Oid>().Select(o => o.Value).ToList();

        Assert.Contains(ClientAuthOid, oids);
        Assert.Contains(BuiltInCertificateAuthority.SmartCardLogonOid, oids);
    }

    [Fact]
    public async Task A_cardholder_with_no_sid_is_refused_rather_than_issued_to()
    {
        // Refusing here is the whole point. Issuing without it produces a
        // certificate that installs cleanly, looks right in every viewer, and
        // logs nobody in.
        using var ca = Authority(CaTopology.TwoTier);
        var context = Request() with
        {
            Subject = new CardholderIdentity("Jan Kowalski", "jkowalski@corp.example", null, null),
        };

        var error = await Assert.ThrowsAsync<IssuancePolicyException>(
            () => ca.IssueAsync(context));

        Assert.Contains("objectSid", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task A_request_for_a_key_the_attestation_does_not_cover_is_refused()
    {
        // The attestation says a key is on hardware. If the request carries a
        // different key, the attestation says nothing about this request - and
        // a software key would be certified as hardware-backed.
        using var ca = Authority(CaTopology.TwoTier);
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var context = Request() with
        {
            Attestation = new AttestedKey(29177301, "9A", other.ExportSubjectPublicKeyInfo(),
                "Once", "Never"),
        };

        await Assert.ThrowsAsync<IssuancePolicyException>(() => ca.IssueAsync(context));
    }

    [Fact]
    public async Task A_certificate_never_outlives_its_issuer()
    {
        using var ca = Authority(CaTopology.TwoTier);
        var issued = await ca.IssueAsync(Request(validityDays: 36500));

        Assert.True(issued.Certificate.NotAfter <= ca.Issuer.NotAfter);
    }

    [Fact]
    public async Task Capabilities_say_this_backend_can_issue_for_logon()
    {
        using var ca = Authority(CaTopology.TwoTier);

        var capabilities = await ca.DescribeAsync();

        Assert.Equal(CaBackend.BuiltIn, capabilities.Backend);
        Assert.True(capabilities.AddsSidExtension);
        Assert.True(capabilities.CanIssueSmartCardLogon);
        Assert.True(capabilities.SupportsRevocation);
    }

    [Fact]
    public async Task Revoking_puts_the_serial_on_the_list()
    {
        var crl = new InMemoryCrlStore(TimeSpan.FromHours(6));
        using var ca = Authority(CaTopology.TwoTier, crl);

        var issued = await ca.IssueAsync(Request());
        await ca.RevokeAsync(new RevocationRequest(issued.SerialNumber,
            Blinky.Pki.X509RevocationReason.KeyCompromise));

        Assert.True(crl.IsRevoked(issued.SerialNumber));

        var document = await ca.GetCrlAsync();
        Assert.NotNull(document);
        Assert.False(document!.IsExpired(DateTimeOffset.UtcNow));
    }

    [Fact]
    public async Task Revoking_twice_is_not_an_error()
    {
        // An operator retrying after a timeout must not be told the
        // certificate is fine.
        var crl = new InMemoryCrlStore(TimeSpan.FromHours(6));
        using var ca = Authority(CaTopology.TwoTier, crl);
        var issued = await ca.IssueAsync(Request());

        var request = new RevocationRequest(issued.SerialNumber,
            Blinky.Pki.X509RevocationReason.KeyCompromise);

        await ca.RevokeAsync(request);
        await ca.RevokeAsync(request);

        Assert.Equal(1, crl.Count);
    }

    [Fact]
    public async Task A_backend_with_no_revocation_list_says_so_instead_of_pretending()
    {
        using var ca = Authority(CaTopology.TwoTier, crl: null);

        Assert.Null(await ca.GetCrlAsync());
        Assert.False((await ca.DescribeAsync()).PublishesCrl);
    }

    [Fact]
    public void A_file_backed_key_is_refused_unless_it_was_asked_for()
    {
        var error = Assert.Throws<CertificateAuthorityException>(
            () => FileCaKeyStore.Open("anything.p12", null, allowFileKeys: false));

        Assert.Contains("AllowFileKeys", error.Message, StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------- helpers

    private static BuiltInCertificateAuthority Authority(CaTopology topology,
        ICrlStore? crl = null)
    {
        var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        var notAfter = DateTimeOffset.UtcNow.AddYears(10);

        // pathlen counts the intermediates that may follow: a two-tier root has
        // one, a single CA has none.
        var root = SelfSignedCa("CN=Test Root CA", notBefore, notAfter,
            pathLength: topology is CaTopology.TwoTier ? 1 : 0);

        if (topology is CaTopology.Single)
        {
            return new BuiltInCertificateAuthority("test", new TestKeyStore(root),
                topology, [Public(root)], crl);
        }

        using var issuingKey = RSA.Create(2048);
        var request = new CertificateRequest("CN=Test Issuing CA", issuingKey,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        var issuing = request.Create(root, notBefore, notAfter, [0x01])
            .CopyWithPrivateKey(issuingKey);

        return new BuiltInCertificateAuthority("test", new TestKeyStore(issuing),
            topology, [Public(issuing), Public(root)], crl);
    }

    private static X509Certificate2 SelfSignedCa(string subject, DateTimeOffset notBefore,
        DateTimeOffset notAfter, int pathLength)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(true, true, pathLength, true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        return request.CreateSelfSigned(notBefore, notAfter);
    }

    /// <summary>Strips the private key, which is what a chain is made of.</summary>
    private static X509Certificate2 Public(X509Certificate2 certificate) =>
        X509CertificateLoader.LoadCertificate(certificate.RawData);

    private static CertificateRequestContext Request(string requestSubject = "CN=whatever",
        int validityDays = 365)
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var csr = new CertificateRequest(requestSubject, key, HashAlgorithmName.SHA256);

        return new CertificateRequestContext(
            csr.CreateSigningRequest(),
            new AttestedKey(29177301, "9A", key.ExportSubjectPublicKeyInfo(), "Once", "Never"),
            new CardholderIdentity("Jan Kowalski", "jkowalski@corp.example",
                "S-1-5-21-1-2-3-1104", "CN=Jan Kowalski,OU=Users,DC=corp,DC=example"),
            new IssuanceProfile("smartcard-logon", "9A", "ECCP256", validityDays,
                [ClientAuthOid, BuiltInCertificateAuthority.SmartCardLogonOid],
                IncludeUpnSan: true, IncludeSidExtension: true));
    }

    /// <summary>
    /// Pulls every printable string out of an otherName structure. Crude on
    /// purpose: the test should fail if the value is missing, not if the
    /// encoding is one nesting deeper than expected.
    /// </summary>
    private static string DecodeOtherNameString(byte[] raw)
    {
        var text = new System.Text.StringBuilder();

        foreach (var b in raw)
        {
            text.Append(b is >= 0x20 and < 0x7F ? (char)b : '.');
        }

        return text.ToString();
    }

    private sealed class TestKeyStore(X509Certificate2 certificate) : ICaKeyStore
    {
        public X509Certificate2 Certificate => certificate;

        public string Description => "test";

        public X509SignatureGenerator CreateSignatureGenerator() =>
            certificate.GetRSAPrivateKey() is { } rsa
                ? X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pkcs1)
                : X509SignatureGenerator.CreateForECDsa(certificate.GetECDsaPrivateKey()!);

        public void Dispose() => certificate.Dispose();
    }
}
