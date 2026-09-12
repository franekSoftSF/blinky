using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Blinky.Pki;
using Blinky.Pki.Adcs;

namespace Blinky.UnitTests;

/// <summary>
/// The enrolment agent's certificate, and the envelope it signs.
/// </summary>
/// <remarks>
/// This is the credential that lets Blinky ask a Microsoft CA for a certificate
/// in somebody else's name, so every refusal here is load-bearing: a store that
/// accepts a certificate ADCS will not honour hands the failure to whoever
/// enrols next, on somebody's desk, holding a card.
/// </remarks>
public sealed class AdcsEnrolmentAgentTests
{
    private const string RequestAgent = "1.3.6.1.4.1.311.20.2.1";

    private const string PkiData = "1.3.6.1.5.5.7.12.2";

    private const string Requester = @"BLINKY\jnowak";

    [Fact]
    public void An_agent_certificate_with_the_request_agent_policy_loads()
    {
        using var file = AdcsTestCertificates.AgentPkcs12();
        using var store = FileEnrolmentAgentKeyStore.Open(file.Path, file.Password, allowFileKeys: true);

        Assert.True(store.Certificate.HasPrivateKey);
        Assert.False(store.Custody.ProductionReady);
        Assert.Contains(file.Path, store.Description, StringComparison.Ordinal);
    }

    [Fact]
    public void A_file_backed_agent_key_is_refused_unless_it_was_asked_for()
    {
        using var file = AdcsTestCertificates.AgentPkcs12();

        var refusal = Assert.Throws<CertificateAuthorityException>(
            () => FileEnrolmentAgentKeyStore.Open(file.Path, file.Password, allowFileKeys: false));

        Assert.Contains("AllowFileKeys", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_certificate_without_the_request_agent_policy_is_refused_by_name()
    {
        // The realistic mistake: an ordinary client-authentication certificate
        // belonging to the service account, which looks right in every way a
        // person checks by eye.
        using var file = AdcsTestCertificates.AgentPkcs12(eku: "1.3.6.1.5.5.7.3.2");

        var refusal = Assert.Throws<CertificateAuthorityException>(
            () => FileEnrolmentAgentKeyStore.Open(file.Path, file.Password, allowFileKeys: true));

        Assert.Contains(RequestAgent, refusal.Message, StringComparison.Ordinal);
        Assert.Contains("Enrollment Agent", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_certificate_with_no_extended_key_usage_at_all_is_refused_too()
    {
        // Absence is not "unrestricted" here. That reading is right for TLS and
        // wrong for this: ADCS looks for the application policy on the
        // signature, so a certificate that names none will be refused by the CA.
        using var file = AdcsTestCertificates.AgentPkcs12(eku: null);

        var refusal = Assert.Throws<CertificateAuthorityException>(
            () => FileEnrolmentAgentKeyStore.Open(file.Path, file.Password, allowFileKeys: true));

        Assert.Contains(RequestAgent, refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void An_expired_agent_certificate_is_refused_with_the_date()
    {
        using var file = AdcsTestCertificates.AgentPkcs12(
            notBefore: DateTimeOffset.UtcNow.AddDays(-800),
            notAfter: DateTimeOffset.UtcNow.AddDays(-1));

        var refusal = Assert.Throws<CertificateAuthorityException>(
            () => FileEnrolmentAgentKeyStore.Open(file.Path, file.Password, allowFileKeys: true));

        Assert.Contains("expired", refusal.Message, StringComparison.Ordinal);
        Assert.Contains("no configuration that turns that off", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_certificate_with_no_private_key_cannot_sign_and_says_so()
    {
        using var file = AdcsTestCertificates.AgentPkcs12(withPrivateKey: false);

        var refusal = Assert.Throws<CertificateAuthorityException>(
            () => FileEnrolmentAgentKeyStore.Open(file.Path, file.Password, allowFileKeys: true));

        Assert.Contains("no private key", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_cmc_carries_the_cardholders_request_untouched_inside_the_agents_signature()
    {
        using var file = AdcsTestCertificates.AgentPkcs12();
        using var store = FileEnrolmentAgentKeyStore.Open(file.Path, file.Password, allowFileKeys: true);

        var pkcs10 = AdcsTestCertificates.CardRequest("CN=jnowak");

        var cmc = await CmcRequest.CreateAsync(pkcs10, Requester, store);

        var signed = new SignedCms();
        signed.Decode(cmc);

        // id-cct-PKIData, not id-data. A CA sent the wrong content type answers
        // with a complaint about the format rather than about the request.
        Assert.Equal(PkiData, signed.ContentInfo.ContentType.Value);

        // Two SignerInfos, as MS-WCCE requires on somebody's behalf: one standing in
        // for the enrollee without a signature, and the agent's. The first version
        // had only the agent's.
        var signers = signed.SignerInfos.Cast<SignerInfo>().ToList();
        Assert.Equal(2, signers.Count);
        Assert.Single(signers, s => s.SignerIdentifier.Type == SubjectIdentifierType.NoSignature);

        var signer = Assert.Single(signers, s => s.SignerIdentifier.Type != SubjectIdentifierType.NoSignature);
        Assert.Equal(store.Certificate.Thumbprint, signer.Certificate?.Thumbprint);
        Verify(signed);

        // And the cardholder's request comes back byte for byte. The whole
        // arrangement rests on the CA seeing a PKCS#10 the card signed; a layer
        // that re-encoded it would break the proof of possession silently.
        Assert.Equal(pkcs10, InnerRequest(signed.ContentInfo.Content));
    }

    [Fact]
    public async Task The_signature_is_sha256_rather_than_whatever_the_default_is()
    {
        using var file = AdcsTestCertificates.AgentPkcs12();
        using var store = FileEnrolmentAgentKeyStore.Open(file.Path, file.Password, allowFileKeys: true);

        var signed = new SignedCms();
        signed.Decode(await CmcRequest.CreateAsync(AdcsTestCertificates.CardRequest("CN=jnowak"), Requester, store));

        Assert.All(signed.SignerInfos.Cast<SignerInfo>(),
            signer => Assert.Equal("2.16.840.1.101.3.4.2.1", signer.DigestAlgorithm.Value));
    }

    [Fact]
    public async Task An_empty_request_is_refused_rather_than_signed()
    {
        using var file = AdcsTestCertificates.AgentPkcs12();
        using var store = FileEnrolmentAgentKeyStore.Open(file.Path, file.Password, allowFileKeys: true);

        var refusal = await Assert.ThrowsAsync<CertificateAuthorityException>(
            () => CmcRequest.CreateAsync([], Requester, store));

        Assert.Contains("no certificate request", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Pki_data_has_all_four_sequences_because_none_of_them_is_optional()
    {
        var pkcs10 = AdcsTestCertificates.CardRequest("CN=jnowak");

        var reader = new AsnReader(CmcRequest.PkiData(pkcs10, Requester), AsnEncodingRules.DER);
        var body = reader.ReadSequence();

        Assert.False(reader.HasData);

        // controlSequence, reqSequence, cmsSequence, otherMsgSequence. The first
        // is no longer empty: it names the requester.
        Assert.True(body.ReadSequence().HasData);

        var requests = body.ReadSequence();
        Assert.True(requests.HasData);

        Assert.False(body.ReadSequence().HasData);
        Assert.False(body.ReadSequence().HasData);
        Assert.False(body.HasData);
    }

    [Fact]
    public void The_tagged_request_is_context_zero_implicit_rather_than_a_wrapped_sequence()
    {
        // RFC 5272's module is IMPLICIT TAGS, so [0] stands in for the SEQUENCE
        // tag of TaggedCertificationRequest. An explicit reading would nest one
        // sequence deeper and a CA rejects the result.
        var reader = new AsnReader(
            CmcRequest.PkiData(AdcsTestCertificates.CardRequest("CN=jnowak"), Requester),
            AsnEncodingRules.DER);

        var body = reader.ReadSequence();
        body.ReadSequence();

        var tagged = body.ReadSequence().ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));

        Assert.Equal(1, tagged.ReadInteger());
    }

    [Fact]
    public void The_template_attribute_names_the_template_the_way_the_ca_reads_it() =>
        Assert.Equal(
            "CertificateTemplate:BlinkySmartcardUser",
            CmcRequest.TemplateAttribute("BlinkySmartcardUser"));

    [Fact]
    public void The_requester_travels_in_a_reginfo_control_the_way_ms_wcce_spells_it()
    {
        // MS-WCCE 2.2.2.6.3: UTF-8, Name=Value, pairs joined by &. Without this the
        // CA issues for whoever called it - with a computer-bound agent, the computer.
        var reader = new AsnReader(
            CmcRequest.PkiData(AdcsTestCertificates.CardRequest("CN=jnowak"), Requester),
            AsnEncodingRules.DER);

        var control = reader.ReadSequence().ReadSequence().ReadSequence();

        Assert.Equal(2, control.ReadInteger());
        Assert.Equal("1.3.6.1.5.5.7.7.18", control.ReadObjectIdentifier());
        Assert.Equal(
            "requestername=" + Requester,
            System.Text.Encoding.UTF8.GetString(control.ReadSetOf().ReadOctetString()));
    }

    [Theory]
    [InlineData(@"BLINKY\jnowak", @"BLINKY\jnowak")]
    [InlineData(@" AD\Administrator ", @"AD\Administrator")]
    public void A_requester_name_is_domain_backslash_account(string given, string expected) =>
        Assert.Equal(expected, CmcRequest.RequesterName(given));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("jnowak")]
    [InlineData("jnowak@blinky.lab")]
    [InlineData(@"\jnowak")]
    [InlineData(@"BLINKY\")]
    [InlineData(@"A\B\C")]
    // The separators of the attribute string. MS-WCCE defines no escape, so a
    // name carrying one would reach the CA as a different name and an extra pair.
    [InlineData(@"BLINKY\j&certificatetemplate=SubCA")]
    [InlineData(@"BLINKY\j=k")]
    public void Anything_else_is_refused_before_it_reaches_the_ca(string? given)
    {
        var refusal = Assert.Throws<IssuancePolicyException>(() => CmcRequest.RequesterName(given));

        Assert.Contains(@"DOMAIN\sAMAccountName", refusal.Message, StringComparison.Ordinal);
    }

/// <summary>
    /// Every SignerInfo checked the way its kind is checked: the agent's by its
    /// signature, the no-signature one by its hash. <c>SignedCms.CheckSignature</c>
    /// looks for a certificate for both and fails on the second with "Cannot find the
    /// original signer", which is true and beside the point.
    /// </summary>
    internal static void Verify(SignedCms signed)
    {
        foreach (SignerInfo signer in signed.SignerInfos)
        {
            if (signer.SignerIdentifier.Type == SubjectIdentifierType.NoSignature)
            {
                signer.CheckHash();
            }
            else
            {
                signer.CheckSignature(verifySignatureOnly: true);
            }
        }
    }

    /// <summary>The PKCS#10 back out of a PKIData, for comparison.</summary>
    private static byte[] InnerRequest(byte[] content)
    {
        var reader = new AsnReader(content, AsnEncodingRules.DER);
        var body = reader.ReadSequence();

        body.ReadSequence();

        var tagged = body.ReadSequence().ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
        tagged.ReadInteger();

        return tagged.ReadEncodedValue().ToArray();
    }
}

/// <summary>
/// Certificates and requests for the ADCS tests, made here rather than kept as
/// fixtures: an expired enrolment agent certificate has to be expired relative
/// to whenever the test runs.
/// </summary>
internal static class AdcsTestCertificates
{
    internal sealed class TempPkcs12 : IDisposable
    {
        public required string Path { get; init; }

        public required string Password { get; init; }

        public void Dispose()
        {
            try
            {
                File.Delete(Path);
            }
            catch (IOException)
            {
                // A leftover file in the temp directory is not worth failing a
                // test that has already made its point.
            }
        }
    }

    public static TempPkcs12 AgentPkcs12(
        string? eku = "1.3.6.1.4.1.311.20.2.1",
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null,
        bool withPrivateKey = true)
    {
        using var key = RSA.Create(2048);

        var request = new CertificateRequest(
            "CN=blinky enrolment agent", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        if (eku is not null)
        {
            request.CertificateExtensions.Add(
                new X509EnhancedKeyUsageExtension([new Oid(eku)], critical: false));
        }

        using var certificate = request.CreateSelfSigned(
            notBefore ?? DateTimeOffset.UtcNow.AddDays(-1),
            notAfter ?? DateTimeOffset.UtcNow.AddDays(365));

        var password = "agent-" + Guid.NewGuid().ToString("n")[..8];
        var path = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(), "blinky-ea-" + Guid.NewGuid().ToString("n") + ".p12");

        // Without the key when that is what the test is about: exporting a
        // certificate that has no private key attached produces exactly the
        // PKCS#12 somebody hands over having exported the wrong thing.
        var bytes = withPrivateKey
            ? certificate.Export(X509ContentType.Pkcs12, password)
            : X509CertificateLoader.LoadCertificate(certificate.RawData)
                .Export(X509ContentType.Pkcs12, password);

        File.WriteAllBytes(path, bytes);

        return new TempPkcs12 { Path = path, Password = password };
    }

    /// <summary>
    /// An enrolment agent certificate without its key - which is all the container
    /// ever sees of one that lives on the connector's server.
    /// </summary>
    public static X509Certificate2 Agent(DateTimeOffset? notBefore = null, DateTimeOffset? notAfter = null)
    {
        using var key = RSA.Create(2048);

        var request = new CertificateRequest(
            "CN=blinky enrolment agent", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            [new Oid("1.3.6.1.4.1.311.20.2.1")], critical: false));

        using var withKey = request.CreateSelfSigned(
            notBefore ?? DateTimeOffset.UtcNow.AddDays(-1),
            notAfter ?? DateTimeOffset.UtcNow.AddDays(365));

        return X509CertificateLoader.LoadCertificate(withKey.RawData);
    }

    /// <summary>A PKCS#10 of the shape a card produces: signed by its own key.</summary>
    public static byte[] CardRequest(string subject)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        return new CertificateRequest(subject, key, HashAlgorithmName.SHA256)
            .CreateSigningRequest();
    }

    /// <summary>A certificate standing in for what a CA returned.</summary>
    public static X509Certificate2 Issued(string subject = "CN=jnowak")
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        return new CertificateRequest(subject, key, HashAlgorithmName.SHA256)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));
    }
}
