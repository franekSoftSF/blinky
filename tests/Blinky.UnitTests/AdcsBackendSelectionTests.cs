using System.Security.Cryptography.X509Certificates;
using Blinky.Contracts;
using Blinky.Domain;
using Blinky.Pki;
using Blinky.Pki.Adcs;

namespace Blinky.UnitTests;

/// <summary>
/// Choosing the Microsoft CA, and everything about that choice that can be
/// refused before anybody enrols.
/// </summary>
/// <remarks>
/// A deployment configured wrongly finds out at start, from a sentence naming the
/// setting, or at the first enrolment, from a CA's denial naming nothing. These
/// are the first kind.
/// </remarks>
public sealed class AdcsBackendSelectionTests
{
    [Theory]
    [InlineData(null, CaBackend.BuiltIn)]
    [InlineData("", CaBackend.BuiltIn)]
    [InlineData("BuiltIn", CaBackend.BuiltIn)]
    [InlineData("builtin", CaBackend.BuiltIn)]
    [InlineData("Adcs", CaBackend.Adcs)]
    [InlineData(" adcs ", CaBackend.Adcs)]
    public void The_backend_is_read_by_name_and_unset_is_the_built_in_ca(
        string? configured, CaBackend expected) =>
        Assert.Equal(expected, AdcsInstance.Backend(configured));

    [Theory]
    [InlineData("Samba")]
    [InlineData("ADCS-CES")]
    // Enum.TryParse would read these as values. A setting that switches the CA
    // on a digit somebody typed is refused rather than obeyed.
    [InlineData("1")]
    [InlineData("0")]
    public void Anything_else_is_refused_rather_than_falling_back_to_the_built_in_ca(string configured)
    {
        // Falling back on a typo would issue certificates from the wrong
        // authority, and the first sign would be a workstation not trusting them.
        var refusal = Assert.Throws<CertificateAuthorityException>(
            () => AdcsInstance.Backend(configured));

        Assert.Contains("neither BuiltIn nor Adcs", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Ces_is_refused_by_name_until_it_exists()
    {
        using var client = AdcsTestCertificates.AgentPkcs12();

        var refusal = Assert.Throws<CertificateAuthorityException>(
            () => AdcsInstance.Create(Options(client, transport: "Ces"), issues: true));

        Assert.Contains("0031", refusal.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("ca01.blinky.lab:8444")]
    [InlineData("http://ca01.blinky.lab:8444")]
    public void The_connector_address_has_to_be_absolute_https(string? url)
    {
        using var client = AdcsTestCertificates.AgentPkcs12();

        var refusal = Assert.Throws<CertificateAuthorityException>(
            () => AdcsInstance.Create(Options(client, url: url), issues: true));

        Assert.Contains("absolute https", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Building_the_ca_does_not_need_the_connector_to_be_up()
    {
        using var client = AdcsTestCertificates.AgentPkcs12();

        // Nothing listens on port 1. The API has to start on the morning the CA
        // server is being patched, and say so at the first enrolment instead.
        using var ca = AdcsInstance.Create(
            Options(client, url: "https://127.0.0.1:1"), issues: true);

        Assert.Equal("lab-adcs", ca.Name);
        Assert.Contains("127.0.0.1:1", ca.AgentDescription, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_ca_built_to_revoke_holds_no_agent_and_refuses_to_issue()
    {
        using var client = AdcsTestCertificates.AgentPkcs12();
        using var ca = AdcsInstance.Create(Options(client), issues: false);

        Assert.Contains("does not issue", ca.AgentDescription, StringComparison.Ordinal);

        var refusal = await Assert.ThrowsAsync<CertificateAuthorityException>(
            () => ca.IssueAsync(Request()));

        Assert.Contains("revoke and not to issue", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void An_agent_in_a_file_is_opened_at_start_and_refused_without_the_opt_in()
    {
        using var client = AdcsTestCertificates.AgentPkcs12();
        using var agent = AdcsTestCertificates.AgentPkcs12();

        var options = Options(client);
        options.EnrolmentAgent = new AdcsEnrolmentAgentOptions
        {
            Location = "File",
            Path = agent.Path,
            Password = agent.Password,
            AllowFileKeys = false,
        };

        var refusal = Assert.Throws<CertificateAuthorityException>(
            () => AdcsInstance.Create(options, issues: true));

        Assert.Contains("AllowFileKeys", refusal.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("File", null, "Path is not set")]
    [InlineData("Vault", null, "neither Connector nor File")]
    public void A_misnamed_agent_location_is_refused_by_setting(
        string location, string? path, string expected)
    {
        using var client = AdcsTestCertificates.AgentPkcs12();

        var options = Options(client);
        options.EnrolmentAgent = new AdcsEnrolmentAgentOptions { Location = location, Path = path };

        var refusal = Assert.Throws<CertificateAuthorityException>(
            () => AdcsInstance.Create(options, issues: true));

        Assert.Contains(expected, refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_profile_without_a_template_takes_the_one_this_instance_maps_it_to()
    {
        var transport = new FakeAdcsTransport();

        using var ca = new AdcsCertificateAuthority(
            "lab-adcs", transport, (IEnrolmentAgentSource?)Agent(),
            new AdcsCaOptions(TemplateMap: new Dictionary<string, string>
            {
                ["smartcard-logon"] = "BlinkySmartcardUser",
            }));

        await ca.IssueAsync(Request(template: null));

        Assert.Equal("CertificateTemplate:BlinkySmartcardUser", transport.LastAttributes);
    }

    [Fact]
    public async Task A_profile_with_no_template_anywhere_names_the_setting_to_add()
    {
        var transport = new FakeAdcsTransport();

        using var ca = new AdcsCertificateAuthority(
            "lab-adcs", transport, (IEnrolmentAgentSource?)Agent());

        var refusal = await Assert.ThrowsAsync<IssuancePolicyException>(
            () => ca.IssueAsync(Request(template: null)));

        Assert.Contains("Blinky:Adcs:Templates:smartcard-logon", refusal.Message, StringComparison.Ordinal);
        Assert.Equal(0, transport.Submissions);
    }

    [Fact]
    public async Task A_connector_that_was_down_is_asked_again_rather_than_remembered_as_down()
    {
        using var certificate = AdcsTestCertificates.Agent();
        var remote = new FlakyRemoteAgent(certificate) { FailuresLeft = 1 };

        using var source = new ConnectorEnrolmentAgentSource(remote, "ca01:8444");

        await Assert.ThrowsAsync<CertificateAuthorityException>(() => source.OpenAsync());

        var store = await source.OpenAsync();

        Assert.Equal(certificate.Thumbprint, store.Certificate.Thumbprint);
        Assert.Equal(2, remote.Describes);
    }

    [Fact]
    public async Task An_agent_that_opened_is_kept_rather_than_asked_for_at_every_enrolment()
    {
        using var certificate = AdcsTestCertificates.Agent();
        var remote = new FlakyRemoteAgent(certificate);

        using var source = new ConnectorEnrolmentAgentSource(remote, "ca01:8444");

        await source.OpenAsync();
        await source.OpenAsync();
        await source.OpenAsync();

        Assert.Equal(1, remote.Describes);
    }

    [Fact]
    public async Task An_agent_that_expired_while_kept_is_dropped_and_the_connector_asked_again()
    {
        using var certificate = AdcsTestCertificates.Agent(
            notBefore: DateTimeOffset.UtcNow.AddDays(-1),
            notAfter: DateTimeOffset.UtcNow.AddDays(30));

        var clock = new ManualClock(DateTimeOffset.UtcNow);
        var remote = new FlakyRemoteAgent(certificate);

        using var source = new ConnectorEnrolmentAgentSource(remote, "ca01:8444", clock);

        await source.OpenAsync();

        // Past the certificate the connector reported. Kept, it would refuse
        // every enrolment with a date; dropped, the connector is asked again and
        // - here still holding the old one - the refusal says so honestly.
        clock.Now = DateTimeOffset.UtcNow.AddDays(60);

        var refusal = await Assert.ThrowsAsync<CertificateAuthorityException>(() => source.OpenAsync());

        Assert.Contains("expired", refusal.Message, StringComparison.Ordinal);
        Assert.Equal(2, remote.Describes);
    }

    [Fact]
    public void A_password_file_wins_over_a_value_and_its_line_ending_is_not_part_of_it()
    {
        var file = Path.Combine(Path.GetTempPath(), "blinky-secret-" + Guid.NewGuid().ToString("n"));

        try
        {
            File.WriteAllText(file, "from-the-file\r\n");

            Assert.Equal("from-the-file", AdcsInstance.Secret("from-the-value", file, "setting"));
            Assert.Equal("from-the-value", AdcsInstance.Secret("from-the-value", null, "setting"));
            Assert.Null(AdcsInstance.Secret(null, "", "setting"));
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Fact]
    public void A_password_file_that_is_not_there_is_refused_by_setting()
    {
        var refusal = Assert.Throws<CertificateAuthorityException>(
            () => AdcsInstance.Secret(null, @"C:\nowhere\secret.txt", "Blinky:Adcs:Connector:ClientCertificatePasswordFile"));

        Assert.Contains("ClientCertificatePasswordFile", refusal.Message, StringComparison.Ordinal);
    }

    private static AdcsInstanceOptions Options(
        AdcsTestCertificates.TempPkcs12 client, string transport = "Connector",
        string? url = "https://ca01.blinky.lab:8444") => new()
    {
        Name = "lab-adcs",
        Transport = transport,
        Connector = new AdcsConnectorOptions
        {
            Url = url,
            ClientCertificatePath = client.Path,
            ClientCertificatePassword = client.Password,
            ServerFingerprint = new string('A', 64),
        },
    };

    private static OpenedEnrolmentAgentSource Agent()
    {
        using var file = AdcsTestCertificates.AgentPkcs12();

        return new OpenedEnrolmentAgentSource(
            FileEnrolmentAgentKeyStore.Open(file.Path, file.Password, allowFileKeys: true));
    }

    private static CertificateRequestContext Request(string? template = "BlinkySmartcardUser") =>
        new(
            AdcsTestCertificates.CardRequest("CN=jnowak"),
            new AttestedKey(12345678, "9A", [1, 2, 3], "Once", "Never"),
            new CardholderIdentity("Jan Nowak", "jnowak@blinky.lab", "S-1-5-21-1-2-3-1104", null, @"BLINKY\jnowak"),
            new IssuanceProfile(
                "smartcard-logon", "9A", "ECCP256", 365,
                ["1.3.6.1.5.5.7.3.2"],
                IncludeUpnSan: true, IncludeSidExtension: true,
                AdcsTemplateName: template));

    private sealed class FlakyRemoteAgent(X509Certificate2 certificate) : IRemoteEnrolmentAgent
    {
        public int FailuresLeft { get; set; }

        public int Describes { get; private set; }

        public Task<AdcsEnrolmentAgentInfo?> DescribeAgentAsync(CancellationToken ct = default)
        {
            Describes++;

            if (FailuresLeft > 0)
            {
                FailuresLeft--;

                throw new CertificateAuthorityException("The connector could not be reached.");
            }

            return Task.FromResult<AdcsEnrolmentAgentInfo?>(new AdcsEnrolmentAgentInfo(
                Convert.ToBase64String(certificate.RawData), "store: CurrentUser\\My", false, "test"));
        }

        public Task<byte[]> SignPkiDataAsync(byte[] pkiData, CancellationToken ct = default) =>
            Task.FromResult(Array.Empty<byte>());
    }

    private sealed class ManualClock(DateTimeOffset start) : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = start;

        public override DateTimeOffset GetUtcNow() => Now;
    }
}
