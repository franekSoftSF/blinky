using System.DirectoryServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Blinky.AdcsConnector;
using Blinky.Contracts;
using Blinky.Pki;
using Blinky.Pki.Adcs;

namespace Blinky.UnitTests;

/// <summary>
/// Patch 0033: a Microsoft CA refused with a named reason before anybody enrols.
/// </summary>
/// <remarks>
/// The definition of done names three refusals - a template that supplies the
/// subject, an enrolment agent that is missing or expired, a service account
/// without Enroll - and each has a test here. So does the rule that makes the
/// check trustworthy on a real estate: what could not be read is a warning, never
/// a refusal and never a pass.
/// </remarks>
public sealed class AdcsRegistrationTests
{
    private const string Template = "BlinkySmartcardUser";

    private static readonly SecurityIdentifier Integration =
        new("S-1-5-21-1111111111-2222222222-3333333333-1105");

    private static readonly SecurityIdentifier EnrolmentGroup =
        new("S-1-5-21-1111111111-2222222222-3333333333-2201");

    private static readonly SecurityIdentifier Stranger =
        new("S-1-5-21-1111111111-2222222222-3333333333-9999");

    [Fact]
    public async Task A_correctly_prepared_ca_is_accepted_with_nothing_to_say()
    {
        var report = await Check(Transport());

        Assert.True(report.Accepted);
        Assert.Empty(report.Findings);
    }

    [Fact]
    public async Task A_template_that_takes_the_subject_from_the_request_is_refused_by_name()
    {
        var report = await Check(Transport(Correct() with { NameFlags = AdcsRegistration.EnrolleeSuppliesSubject }));

        var finding = Refusal(report, "template-supplies-subject");
        Assert.Contains("SID extension", finding.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_template_the_account_cannot_enrol_for_is_refused_naming_the_account()
    {
        var report = await Check(Transport(Correct() with { AccountMayEnroll = false }));

        var finding = Refusal(report, "account-cannot-enroll");
        Assert.Contains("LAB\\svc-blinky", finding.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_missing_enrolment_agent_is_refused()
    {
        var report = await Check(Transport(), agents: new FailingAgents(
            "The connector at ca01:8444 holds no enrolment agent."));

        Assert.False(report.Accepted);
        Assert.Contains("holds no enrolment agent", Refusal(report, "agent-unusable").Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_expired_enrolment_agent_is_refused()
    {
        using var file = AdcsTestCertificates.AgentPkcs12(
            notBefore: DateTimeOffset.UtcNow.AddDays(-800),
            notAfter: DateTimeOffset.UtcNow.AddDays(-1));

        // The file store refuses at open, which is what an expired agent on the
        // connector's side produces too.
        var agents = new FailingAgents(Assert.Throws<CertificateAuthorityException>(
            () => FileEnrolmentAgentKeyStore.Open(file.Path, file.Password, allowFileKeys: true)).Message);

        var report = await Check(Transport(), agents: agents);

        Assert.Contains("expired", Refusal(report, "agent-unusable").Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_template_requiring_no_agent_signature_is_refused()
    {
        // The CA would issue on the requesting account's own authority, and the
        // enrolment agent's signature would prove nothing.
        var report = await Check(Transport(Correct() with { AuthorizedSignatures = 0 }));

        Refusal(report, "template-no-agent-signature");
    }

    [Fact]
    public async Task A_signature_under_the_wrong_application_policy_is_refused()
    {
        var report = await Check(Transport(Correct() with { SignaturePolicies = ["1.3.6.1.5.5.7.3.2"] }));

        Refusal(report, "template-wrong-signature-policy");
    }

    [Fact]
    public async Task The_request_agent_policy_is_found_inside_a_version_4_encoding()
    {
        // Version 4 templates pack more than OIDs into the attribute. A check that
        // compared whole values would refuse every one of them.
        var report = await Check(Transport(Correct() with
        {
            SchemaVersion = 4,
            SignaturePolicies = ["msPKI-Asymmetric-Algorithm`PZPWSTR`RSA`msPKI-RA-Application-Policies`PZPWSTR`1.3.6.1.4.1.311.20.2.1`"],
        }));

        Assert.True(report.Accepted);
    }

    [Fact]
    public async Task A_template_that_does_not_exist_is_refused_with_the_name_versus_display_name_hint()
    {
        var transport = Transport();
        transport.TemplateObjects.Clear();

        var report = await Check(transport);

        Assert.Contains("display name", Refusal(report, "template-not-found").Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_template_the_ca_does_not_issue_is_refused()
    {
        var transport = new FakeAdcsTransport { PublishedTemplates = ["User", "Computer"] };
        transport.TemplateObjects[Template] = Correct();

        var report = await Check(transport);

        Refusal(report, "template-not-published");
    }

    [Fact]
    public async Task Unreadable_attributes_are_warnings_rather_than_refusals_or_passes()
    {
        var transport = new FakeAdcsTransport { PublishedTemplates = null };
        transport.TemplateObjects[Template] = new AdcsTemplateInfo(Template, Found: true, Account: "LAB\\svc-blinky");

        var report = await Check(transport);

        // Not refused, and not accepted either. The first run of this check
        // against a machine with no domain reported "accepted" with nothing
        // verified, because only refusals were counted.
        Assert.Equal(RegistrationOutcome.Unverified, report.Outcome);
        Assert.False(report.Accepted);
        Assert.All(report.Findings, finding => Assert.Equal(RegistrationSeverity.Unknown, finding.Severity));

        // Publication, name flags, signatures and the Enroll right: four things
        // not established, four sentences saying so.
        Assert.Contains(report.Findings, f => f.Code == "template-publication-unknown");
        Assert.Equal(3, report.Findings.Count(f => f.Code == "template-attribute-unknown"));
    }

    [Fact]
    public async Task A_ca_that_does_not_hand_over_its_own_certificate_leaves_the_registration_unverified()
    {
        // The connector answered and the CA behind it did not: a config string
        // naming a CA that is not there looks exactly like this.
        var transport = new FakeAdcsTransport { CaChain = null };
        transport.TemplateObjects[Template] = Correct();

        var report = await Check(transport);

        Assert.Equal(RegistrationOutcome.Unverified, report.Outcome);
        Assert.Equal("ca-certificate-unavailable", Assert.Single(report.Findings).Code);
    }

    [Fact]
    public async Task An_unreachable_ca_is_one_refusal_rather_than_a_dozen_unknowns()
    {
        var transport = new FakeAdcsTransport
        {
            DescribeFault = new CertificateAuthorityException("The connector at ca01:8444 could not be reached."),
        };

        var report = await Check(transport);

        var finding = Assert.Single(report.Findings);
        Assert.Equal("ca-unreachable", finding.Code);
    }

    [Fact]
    public async Task No_mapped_template_is_refused_because_nothing_could_be_issued()
    {
        var report = await Check(Transport(), templates: []);

        Refusal(report, "no-template");
    }

    [Fact]
    public async Task An_empty_mapping_names_the_profile_it_leaves_unissuable()
    {
        var report = await Check(Transport(), templates: new() { ["smartcard-logon"] = "" });

        Assert.Contains("smartcard-logon", Refusal(report, "template-unmapped").Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Revocation_the_account_cannot_perform_is_a_warning_not_a_refusal()
    {
        // Enrolment works without it; the console should say revoking will not
        // reach the CA rather than refuse the CA outright.
        var transport = Transport();
        var unrevocable = new FakeAdcsTransport { AdminAvailable = false };
        unrevocable.TemplateObjects[Template] = transport.TemplateObjects[Template];

        var report = await Check(unrevocable);

        Assert.True(report.Accepted);
        Assert.Equal(RegistrationSeverity.Warning,
            Assert.Single(report.Findings, f => f.Code == "revocation-unavailable").Severity);
    }

    [Fact]
    public async Task An_agent_in_a_file_is_accepted_with_a_warning_about_where_it_is()
    {
        using var file = AdcsTestCertificates.AgentPkcs12();
        using var agents = new OpenedEnrolmentAgentSource(
            FileEnrolmentAgentKeyStore.Open(file.Path, file.Password, allowFileKeys: true));

        var report = await Check(Transport(), agents: agents);

        Assert.True(report.Accepted);
        Assert.Equal("agent-custody", Assert.Single(report.Findings).Code);
    }

    [Fact]
    public void Enroll_granted_directly_to_the_account_is_found()
    {
        var security = Descriptor($"(OA;;CR;{EnrolRight.Enroll};;{Integration})");

        Assert.True(EnrolRight.Evaluate(security, Token(Integration)));
    }

    [Fact]
    public void Enroll_granted_to_a_group_the_account_is_in_is_found()
    {
        var security = Descriptor($"(OA;;CR;{EnrolRight.Enroll};;{EnrolmentGroup})");

        Assert.True(EnrolRight.Evaluate(security, Token(Integration, EnrolmentGroup)));
    }

    [Fact]
    public void Enroll_granted_to_somebody_else_is_not_the_accounts()
    {
        var security = Descriptor($"(OA;;CR;{EnrolRight.Enroll};;{Stranger})");

        Assert.False(EnrolRight.Evaluate(security, Token(Integration, EnrolmentGroup)));
    }

    [Fact]
    public void Full_control_and_all_extended_rights_both_grant_enroll()
    {
        // The two common over-grants. A check that looked only for the Enroll GUID
        // would call either of these a refusal while the CA happily issued.
        //
        // Full Control is written the way the directory stores it, as the mapped
        // rights. The first version of this test used SDDL GA - the generic bit
        // the directory never stores - and failed against correct code.
        Assert.True(EnrolRight.Evaluate(
            Descriptor($"(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;{Integration})"), Token(Integration)));
        Assert.True(EnrolRight.Evaluate(Descriptor($"(A;;CR;;;{Integration})"), Token(Integration)));

        // And the unmapped bit, from a descriptor a tool wrote without mapping it.
        Assert.True(EnrolRight.Evaluate(Descriptor($"(A;;GA;;;{Integration})"), Token(Integration)));
    }

    [Fact]
    public void A_deny_on_a_group_beats_an_allow_on_the_account()
    {
        var security = Descriptor(
            $"(OA;;CR;{EnrolRight.Enroll};;{Integration})(OD;;CR;{EnrolRight.Enroll};;{EnrolmentGroup})");

        Assert.False(EnrolRight.Evaluate(security, Token(Integration, EnrolmentGroup)));
    }

    [Fact]
    public void Read_access_alone_is_not_enroll()
    {
        // Authenticated Users read every template. That is not permission to enrol.
        var security = Descriptor($"(A;;RPLCLORC;;;{Integration})");

        Assert.False(EnrolRight.Evaluate(security, Token(Integration)));
    }

    [Theory]
    [InlineData("BlinkySmartcardUser", "BlinkySmartcardUser")]
    [InlineData("a*b", @"a\2ab")]
    [InlineData("x)(cn=*", @"x\29\28cn=\2a")]
    public void A_template_name_is_escaped_before_it_reaches_the_filter(string name, string expected) =>
        Assert.Equal(expected, ActiveDirectoryTemplates.Escape(name));

    private static Task<RegistrationReport> Check(
        FakeAdcsTransport transport, IEnrolmentAgentSource? agents = null,
        Dictionary<string, string>? templates = null) =>
        AdcsRegistration.CheckAsync(
            "lab-adcs",
            transport,
            agents,
            new AdcsCaOptions(TemplateMap: templates ?? new Dictionary<string, string>
            {
                ["smartcard-logon"] = Template,
            }));

    private static FakeAdcsTransport Transport(AdcsTemplateInfo? template = null)
    {
        var transport = new FakeAdcsTransport();
        transport.TemplateObjects[Template] = template ?? Correct();

        return transport;
    }

    /// <summary>A copy of Smartcard User prepared the way docs/04 asks.</summary>
    private static AdcsTemplateInfo Correct() => new(
        Template,
        Found: true,
        DisplayName: "Blinky Smartcard User",
        SchemaVersion: 2,
        NameFlags: unchecked((int)0x82000000),
        AuthorizedSignatures: 1,
        SignaturePolicies: [AdcsRegistration.CertificateRequestAgent],
        ExtendedKeyUsages: ["1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.20.2.2"],
        AccountMayEnroll: true,
        Account: "LAB\\svc-blinky");

    private static RegistrationFinding Refusal(RegistrationReport report, string code)
    {
        Assert.False(report.Accepted);

        var finding = Assert.Single(report.Findings, f => f.Code == code);
        Assert.Equal(RegistrationSeverity.Refusal, finding.Severity);

        return finding;
    }

    private static ActiveDirectorySecurity Descriptor(string aces)
    {
        var security = new ActiveDirectorySecurity();
        security.SetSecurityDescriptorSddlForm("D:" + aces, AccessControlSections.Access);

        return security;
    }

    private static HashSet<SecurityIdentifier> Token(params SecurityIdentifier[] sids) => [.. sids];

    private sealed class FailingAgents(string message) : IEnrolmentAgentSource
    {
        public string Description => "failing";

        public Task<IEnrolmentAgentKeyStore> OpenAsync(CancellationToken ct = default) =>
            Task.FromException<IEnrolmentAgentKeyStore>(new CertificateAuthorityException(message));
    }
}
