using System.Formats.Asn1;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Blinky.AdcsConnector;
using Blinky.Contracts;
using Blinky.Pki;
using Blinky.Pki.Adcs;
using Blinky.Pki.BuiltIn;

namespace Blinky.UnitTests;

/// <summary>
/// The enrolment agent on the connector's Windows server, signing what the
/// container built.
/// </summary>
/// <remarks>
/// The arrangement moves a key and must not move a decision. So most of these are
/// about what the connector refuses to sign - because whoever holds an allowed
/// client certificate can ask it - and one of them carries a request from
/// <c>AdcsCertificateAuthority</c> through the connector's real signer and back.
/// </remarks>
public sealed class AdcsRemoteEnrolmentAgentTests
{
    private const string PkiDataOid = "1.3.6.1.5.5.7.12.2";

    [Fact]
    public void The_pki_data_blinky_builds_is_accepted_and_named()
    {
        var pkcs10 = AdcsTestCertificates.CardRequest("CN=jnowak");

        var inspected = PkiDataInspection.Inspect(CmcRequest.PkiData(pkcs10, 1));

        Assert.Equal(1u, inspected.BodyPartId);
        Assert.Equal("CN=jnowak", inspected.Subject);
        Assert.Equal(64, inspected.PublicKeySha256.Length);
    }

    [Fact]
    public void A_control_is_refused_because_a_control_can_be_a_revocation()
    {
        var refusal = Assert.Throws<PkiDataRefusedException>(
            () => PkiDataInspection.Inspect(Build(controls: true)));

        Assert.Contains("revocation request", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Two_requests_under_one_signature_are_refused()
    {
        var refusal = Assert.Throws<PkiDataRefusedException>(
            () => PkiDataInspection.Inspect(Build(requests: 2)));

        Assert.Contains("more than one", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void No_request_at_all_is_refused()
    {
        var refusal = Assert.Throws<PkiDataRefusedException>(
            () => PkiDataInspection.Inspect(Build(requests: 0)));

        Assert.Contains("no certification request", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Nested_signed_content_is_refused_because_it_would_not_have_been_read()
    {
        var refusal = Assert.Throws<PkiDataRefusedException>(
            () => PkiDataInspection.Inspect(Build(nestedContent: true)));

        Assert.Contains("wraps other signed content", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_crmf_request_is_refused_rather_than_signed_unread()
    {
        var refusal = Assert.Throws<PkiDataRefusedException>(
            () => PkiDataInspection.Inspect(Build(requestTag: 1)));

        Assert.Contains("not a PKCS#10", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Bytes_after_the_pki_data_are_refused()
    {
        var refusal = Assert.Throws<PkiDataRefusedException>(
            () => PkiDataInspection.Inspect(Build(trailing: true)));

        Assert.Contains("bytes after", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_request_whose_own_signature_does_not_verify_is_not_vouched_for()
    {
        var broken = AdcsTestCertificates.CardRequest("CN=jnowak");

        // The last byte is inside the signature BIT STRING.
        broken[^1] ^= 0xFF;

        var refusal = Assert.Throws<PkiDataRefusedException>(
            () => PkiDataInspection.Inspect(CmcRequest.PkiData(broken, 1)));

        Assert.Contains("does not verify", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Garbage_is_refused_with_a_sentence_rather_than_an_asn1_exception()
    {
        var refusal = Assert.Throws<PkiDataRefusedException>(
            () => PkiDataInspection.Inspect(new byte[] { 0x01, 0x02, 0x03 }));

        Assert.Contains("not a well-formed PKIData", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void The_connectors_signature_verifies_and_carries_the_request_untouched()
    {
        using var agent = AgentWithKey();
        using var signer = EnrolmentAgentSigner.FromCertificate(agent, "test", DateTimeOffset.UtcNow);

        var pkcs10 = AdcsTestCertificates.CardRequest("CN=jnowak");
        var pkiData = CmcRequest.PkiData(pkcs10, 1);

        var (signedData, inspected) = signer.Sign(pkiData, DateTimeOffset.UtcNow);

        var signed = new SignedCms();
        signed.Decode(signedData);
        signed.CheckSignature(verifySignatureOnly: true);

        Assert.Equal(PkiDataOid, signed.ContentInfo.ContentType.Value);
        Assert.Equal(pkiData, signed.ContentInfo.Content);
        Assert.Equal(agent.Thumbprint, signed.SignerInfos[0].Certificate?.Thumbprint);
        Assert.Equal("2.16.840.1.101.3.4.2.1", signed.SignerInfos[0].DigestAlgorithm.Value);
        Assert.Equal("CN=jnowak", inspected.Subject);
    }

    [Fact]
    public void A_signature_is_refused_once_the_agent_has_expired_while_running()
    {
        using var agent = AgentWithKey();
        using var signer = EnrolmentAgentSigner.FromCertificate(agent, "test", DateTimeOffset.UtcNow);

        // Valid at start, expired at the moment of signing: a service that runs
        // for a year outlives the certificate it started with.
        var refusal = Assert.Throws<InvalidOperationException>(
            () => signer.Sign(
                CmcRequest.PkiData(AdcsTestCertificates.CardRequest("CN=jnowak"), 1),
                DateTimeOffset.UtcNow.AddYears(5)));

        Assert.Contains("expired", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_file_on_the_connector_is_refused_unless_it_was_asked_for()
    {
        using var file = AdcsTestCertificates.AgentPkcs12();

        var refusal = Assert.Throws<InvalidOperationException>(
            () => EnrolmentAgentSigner.Load(
                new EnrolmentAgentOptions { Path = file.Path, Password = file.Password },
                DateTimeOffset.UtcNow));

        Assert.Contains("AllowFileKey", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void An_unconfigured_connector_has_no_agent_rather_than_a_broken_one() =>
        Assert.Null(EnrolmentAgentSigner.Load(new EnrolmentAgentOptions(), DateTimeOffset.UtcNow));

    public static TheoryData<string, string?, int, int, bool, bool> AgentCertificates => new()
    {
        { "valid", "1.3.6.1.4.1.311.20.2.1", -1, 365, true, true },
        { "client authentication only", "1.3.6.1.5.5.7.3.2", -1, 365, true, false },
        { "no extended key usage", null, -1, 365, true, false },
        { "expired", "1.3.6.1.4.1.311.20.2.1", -800, -1, true, false },
        { "not yet valid", "1.3.6.1.4.1.311.20.2.1", 10, 365, true, false },
        { "no private key", "1.3.6.1.4.1.311.20.2.1", -1, 365, false, false },
    };

    [Theory]
    [MemberData(nameof(AgentCertificates))]
    public void The_connector_and_the_container_refuse_the_same_agent_certificates(
        string what, string? eku, int notBeforeDays, int notAfterDays, bool withKey, bool accepted)
    {
        // The rules are duplicated, because the connector deliberately does not
        // reference Blinky.Pki. This is what stops the copies drifting: a
        // certificate one side accepts and the other refuses would pass
        // registration and fail at somebody's enrolment.
        using var file = AdcsTestCertificates.AgentPkcs12(
            eku,
            DateTimeOffset.UtcNow.AddDays(notBeforeDays),
            DateTimeOffset.UtcNow.AddDays(notAfterDays),
            withKey);

        var container = Accepts(() => FileEnrolmentAgentKeyStore
            .Open(file.Path, file.Password, allowFileKeys: true).Dispose());

        var connector = Accepts(() => EnrolmentAgentSigner.Load(
            new EnrolmentAgentOptions { Path = file.Path, Password = file.Password, AllowFileKey = true },
            DateTimeOffset.UtcNow)?.Dispose());

        Assert.True(accepted == container, $"container on {what}");
        Assert.True(accepted == connector, $"connector on {what}");
    }

    [Fact]
    public void Export_policy_is_decided_at_import_rather_than_inherited_from_the_file()
    {
        // Written expecting the opposite, and wrong: the same PKCS#12 loaded
        // twice gives one key that may leave and one that may not, depending only
        // on the flag at import. So "was it exported from somewhere" says nothing
        // about the key on the server, and reading the policy off the key is the
        // only way to know.
        using var file = AdcsTestCertificates.AgentPkcs12();

        using var imported = EnrolmentAgentSigner.Load(
            new EnrolmentAgentOptions { Path = file.Path, Password = file.Password, AllowFileKey = true },
            DateTimeOffset.UtcNow)!;

        using var exportable = EnrolmentAgentSigner.FromCertificate(
            X509CertificateLoader.LoadPkcs12FromFile(
                file.Path, file.Password, X509KeyStorageFlags.Exportable),
            "test",
            DateTimeOffset.UtcNow);

        Assert.False(imported.Exportable);
        Assert.True(exportable.Exportable);
        Assert.False(string.IsNullOrEmpty(imported.Provider));
    }

    [Fact]
    public async Task A_connector_with_no_agent_is_refused_at_open_with_what_to_set()
    {
        var refusal = await Assert.ThrowsAsync<CertificateAuthorityException>(
            () => ConnectorEnrolmentAgentKeyStore.OpenAsync(new FakeRemoteAgent(), "ca01:8444"));

        Assert.Contains("holds no enrolment agent", refusal.Message, StringComparison.Ordinal);
        Assert.Contains("Connector:EnrolmentAgent:Thumbprint", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_expired_agent_on_the_connector_is_refused_before_anything_is_signed()
    {
        using var agent = AdcsTestCertificates.Agent(
            notBefore: DateTimeOffset.UtcNow.AddDays(-800),
            notAfter: DateTimeOffset.UtcNow.AddDays(-1));
        var remote = new FakeRemoteAgent { Agent = Info(agent, exportable: false) };

        var refusal = await Assert.ThrowsAsync<CertificateAuthorityException>(
            () => ConnectorEnrolmentAgentKeyStore.OpenAsync(remote, "ca01:8444"));

        Assert.Contains("expired", refusal.Message, StringComparison.Ordinal);
        Assert.Equal(0, remote.Signatures);
    }

    [Fact]
    public async Task Anything_but_pki_data_is_refused_locally_without_a_round_trip()
    {
        using var agent = AdcsTestCertificates.Agent();
        var remote = new FakeRemoteAgent { Agent = Info(agent, exportable: false) };

        using var store = await ConnectorEnrolmentAgentKeyStore.OpenAsync(remote, "ca01:8444");

        var refusal = await Assert.ThrowsAsync<CertificateAuthorityException>(
            () => store.SignCmsAsync(new ContentInfo([1, 2, 3])));

        Assert.Contains("signs PKIData", refusal.Message, StringComparison.Ordinal);
        Assert.Equal(0, remote.Signatures);
    }

    [Theory]
    [InlineData("store: CurrentUser\\My", false, KeyCustodyTier.WindowsKeyStore, true)]
    [InlineData("store: CurrentUser\\My", true, KeyCustodyTier.WindowsKeyStore, false)]
    [InlineData("store: CurrentUser\\My", null, KeyCustodyTier.WindowsKeyStore, false)]
    [InlineData("file: C:\\lab\\agent.p12", false, KeyCustodyTier.File, false)]
    public void Custody_is_read_from_the_key_rather_than_from_where_it_is(
        string source, bool? exportable, KeyCustodyTier tier, bool productionReady)
    {
        // On the Windows server is not the same as safe. Whether a key may leave
        // was decided by whoever imported it, and a provider that will not say is
        // not reported as one that forbids it.
        var custody = ConnectorEnrolmentAgentKeyStore.CustodyOf(
            new AdcsEnrolmentAgentInfo("AA==", source, exportable, "Microsoft Software Key Storage Provider"));

        Assert.Equal(tier, custody.Tier);
        Assert.Equal(productionReady, custody.ProductionReady);
    }

    [Fact]
    public async Task An_issuance_is_signed_by_the_connector_and_submitted_whole()
    {
        // The whole arrangement in one process: the container builds the PKIData,
        // the connector's real signer signs it with a key the container never
        // holds, and the CA class submits what came back.
        using var agent = AgentWithKey();
        using var signer = EnrolmentAgentSigner.FromCertificate(agent, "store: CurrentUser\\My", DateTimeOffset.UtcNow);

        var remote = new FakeRemoteAgent
        {
            Agent = signer.Describe(),
            Sign = pkiData => signer.Sign(pkiData, DateTimeOffset.UtcNow).SignedData,
        };

        var transport = new FakeAdcsTransport();
        var pkcs10 = AdcsTestCertificates.CardRequest("CN=jnowak");

        using var store = await ConnectorEnrolmentAgentKeyStore.OpenAsync(remote, "ca01:8444");
        using var ca = new AdcsCertificateAuthority("lab-adcs", transport, store);

        await ca.IssueAsync(new CertificateRequestContext(
            pkcs10,
            new AttestedKey(12345678, "9A", [1, 2, 3], "Once", "Never"),
            new CardholderIdentity("Jan Nowak", "jnowak@blinky.lab", "S-1-5-21-1-2-3-1104", null),
            new IssuanceProfile(
                "smartcard-logon", "9A", "ECCP256", 365,
                ["1.3.6.1.5.5.7.3.2"],
                IncludeUpnSan: true, IncludeSidExtension: true,
                AdcsTemplateName: "BlinkySmartcardUser")));

        Assert.Equal(1, remote.Signatures);

        var submitted = new SignedCms();
        submitted.Decode(transport.LastRequest!);
        submitted.CheckSignature(verifySignatureOnly: true);

        Assert.Equal(agent.Thumbprint, submitted.SignerInfos[0].Certificate?.Thumbprint);
        Assert.Equal(CmcRequest.PkiData(pkcs10, 1), submitted.ContentInfo.Content);
        Assert.False(store.Certificate.HasPrivateKey);
    }

    [Fact]
    public async Task The_transport_asks_the_connector_to_sign_pki_data_in_base64()
    {
        var handler = StubHandler.Returning(Json(new AdcsSignResponse(Convert.ToBase64String([9, 9, 9]))));
        using var transport = new ConnectorAdcsTransport(
            new ConnectorTransportOptions(new Uri("https://ca01.blinky.lab:8444")), handler);

        var signed = await transport.SignPkiDataAsync([1, 2, 3]);

        Assert.Equal([9, 9, 9], signed);
        Assert.Equal("/connector/sign", handler.LastRequest!.RequestUri!.AbsolutePath);

        var sent = JsonSerializer.Deserialize<AdcsSignRequest>(
            handler.LastBody!, new JsonSerializerOptions(JsonSerializerDefaults.Web))!;

        Assert.Equal(AdcsTransport.SchemaVersion, sent.SchemaVersion);
        Assert.Equal(Convert.ToBase64String([1, 2, 3]), sent.PkiData);
    }

    [Fact]
    public async Task A_connector_that_holds_no_agent_says_so_through_the_transport()
    {
        var handler = StubHandler.Returning(Json(
            new AdcsProblem("This connector holds no enrolment agent."),
            HttpStatusCode.Conflict));

        using var transport = new ConnectorAdcsTransport(
            new ConnectorTransportOptions(new Uri("https://ca01.blinky.lab:8444")), handler);

        var failure = await Assert.ThrowsAsync<CertificateAuthorityException>(
            () => transport.SignPkiDataAsync([1, 2, 3]));

        Assert.Contains("409", failure.Message, StringComparison.Ordinal);
        Assert.Contains("holds no enrolment agent", failure.Message, StringComparison.Ordinal);
    }

    private static bool Accepts(Action open)
    {
        try
        {
            open();

            return true;
        }
        catch (Exception ex) when (ex is CertificateAuthorityException or InvalidOperationException)
        {
            return false;
        }
    }

    private static X509Certificate2 AgentWithKey()
    {
        using var file = AdcsTestCertificates.AgentPkcs12();

        return X509CertificateLoader.LoadPkcs12FromFile(file.Path, file.Password);
    }

    private static AdcsEnrolmentAgentInfo Info(X509Certificate2 certificate, bool? exportable) =>
        new(Convert.ToBase64String(certificate.RawData), "store: CurrentUser\\My", exportable, "test");

    /// <summary>
    /// A PKIData shaped wrong in exactly one way, to prove each refusal on its own.
    /// </summary>
    private static byte[] Build(
        bool controls = false, int requests = 1, int requestTag = 0, bool nestedContent = false,
        bool trailing = false)
    {
        var pkcs10 = AdcsTestCertificates.CardRequest("CN=jnowak");
        var writer = new AsnWriter(AsnEncodingRules.DER);

        using (writer.PushSequence())
        {
            using (writer.PushSequence())
            {
                if (controls)
                {
                    // TaggedAttribute: bodyPartID, id-cmc-revokeRequest, a value.
                    using (writer.PushSequence())
                    {
                        writer.WriteInteger(1);
                        writer.WriteObjectIdentifier("1.3.6.1.5.5.7.7.17");
                        using (writer.PushSetOf())
                        {
                            writer.WriteNull();
                        }
                    }
                }
            }

            using (writer.PushSequence())
            {
                for (var index = 0; index < requests; index++)
                {
                    using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, requestTag)))
                    {
                        writer.WriteInteger(index + 1);
                        writer.WriteEncodedValue(pkcs10);
                    }
                }
            }

            using (writer.PushSequence())
            {
                if (nestedContent)
                {
                    using (writer.PushSequence())
                    {
                        writer.WriteInteger(2);
                        writer.WriteNull();
                    }
                }
            }

            using (writer.PushSequence())
            {
            }
        }

        var encoded = writer.Encode();

        return trailing ? [.. encoded, 0x00] : encoded;
    }

    private static HttpResponseMessage Json<T>(T body, HttpStatusCode status = HttpStatusCode.OK) =>
        new(status)
        {
            Content = new StringContent(
                JsonSerializer.Serialize(body, new JsonSerializerOptions(JsonSerializerDefaults.Web)),
                Encoding.UTF8,
                "application/json"),
            ReasonPhrase = status.ToString(),
        };

    private sealed class FakeRemoteAgent : IRemoteEnrolmentAgent
    {
        public AdcsEnrolmentAgentInfo? Agent { get; init; }

        public Func<byte[], byte[]> Sign { get; init; } = _ => [];

        public int Signatures { get; private set; }

        public Task<AdcsEnrolmentAgentInfo?> DescribeAgentAsync(CancellationToken ct = default) =>
            Task.FromResult(Agent);

        public Task<byte[]> SignPkiDataAsync(byte[] pkiData, CancellationToken ct = default)
        {
            Signatures++;

            return Task.FromResult(Sign(pkiData));
        }
    }
}
