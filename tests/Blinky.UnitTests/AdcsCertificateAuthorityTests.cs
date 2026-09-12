using System.Security.Cryptography.X509Certificates;
using Blinky.Contracts;
using Blinky.Domain;
using Blinky.Pki;
using Blinky.Pki.Adcs;

namespace Blinky.UnitTests;

/// <summary>
/// What Blinky does with what a Microsoft CA answered.
/// </summary>
/// <remarks>
/// No CA here, and none needed for any of this: every one of these is a decision
/// this side of the wire. The transport is a stub that returns the dispositions
/// ADCS actually returns, which is the part that cannot be exercised on a bench
/// with no Windows AD.
/// </remarks>
public sealed class AdcsCertificateAuthorityTests
{
    private static AdcsCertificateAuthority Ca(
        FakeAdcsTransport transport, AdcsCaOptions? options = null)
    {
        var file = AdcsTestCertificates.AgentPkcs12();
        var agent = FileEnrolmentAgentKeyStore.Open(file.Path, file.Password, allowFileKeys: true);

        // The temp file has done its job once the store is open.
        file.Dispose();

        return new AdcsCertificateAuthority("lab-adcs", transport, agent, options);
    }

    private static CertificateRequestContext Request(string? template = "BlinkySmartcardUser") =>
        new(
            AdcsTestCertificates.CardRequest("CN=jnowak"),
            new AttestedKey(12345678, "9A", [1, 2, 3], "Once", "Never"),
            new CardholderIdentity("Jan Nowak", "jnowak@blinky.lab", "S-1-5-21-1-2-3-1104", null, @"BLINKY\jnowak"),
            new IssuanceProfile(
                "smartcard-logon", "9A", "ECCP256", 365,
                ["1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.20.2.2"],
                IncludeUpnSan: true, IncludeSidExtension: true,
                AdcsTemplateName: template));

    [Fact]
    public async Task The_backend_never_claims_to_publish_a_revocation_list()
    {
        using var ca = Ca(new FakeAdcsTransport());

        var capabilities = await ca.DescribeAsync();

        // ADCS keeps its own list at its own distribution point. A true here
        // would put a link in the console to a file nobody writes.
        Assert.False(capabilities.PublishesCrl);
        Assert.Equal(CaBackend.Adcs, capabilities.Backend);
    }

    [Fact]
    public async Task The_subject_is_never_supplied_in_the_request()
    {
        using var ca = Ca(new FakeAdcsTransport());

        var capabilities = await ca.DescribeAsync();

        // A template configured to take the subject from the request emits no
        // SID extension, and its certificates then fail to log anybody in.
        Assert.False(capabilities.SupportsSuppliedSubject);
        Assert.True(capabilities.AddsSidExtension);
        Assert.True(capabilities.CanIssueSmartCardLogon);
    }

    [Fact]
    public async Task Revocation_is_offered_only_when_the_ca_said_the_account_may_manage()
    {
        using var granted = Ca(new FakeAdcsTransport { AdminAvailable = true });
        using var refused = Ca(new FakeAdcsTransport { AdminAvailable = false });

        Assert.True((await granted.DescribeAsync()).SupportsRevocation);

        // Issue and Manage Certificates is a separate grant from Request
        // Certificates and is routinely missing. The console greys the action
        // out rather than offering a button that fails.
        Assert.False((await refused.DescribeAsync()).SupportsRevocation);
    }

    [Fact]
    public async Task A_deployment_that_forbids_revoking_at_the_ca_reports_it_even_when_allowed()
    {
        using var ca = Ca(
            new FakeAdcsTransport { AdminAvailable = true },
            new AdcsCaOptions(AllowRevocation: false));

        Assert.False((await ca.DescribeAsync()).SupportsRevocation);
    }

    [Fact]
    public async Task A_profile_with_no_template_is_refused_before_anything_reaches_the_ca()
    {
        var transport = new FakeAdcsTransport();
        using var ca = Ca(transport);

        var refusal = await Assert.ThrowsAsync<IssuancePolicyException>(
            () => ca.IssueAsync(Request(template: null)));

        Assert.Contains("names no ADCS template", refusal.Message, StringComparison.Ordinal);
        Assert.Equal(0, transport.Submissions);
    }

    [Fact]
    public async Task A_cardholder_with_no_logon_name_is_refused_before_anything_is_signed()
    {
        // A CMC that names nobody is issued for whoever called the CA. Better a
        // sentence naming the missing directory attribute than that.
        var transport = new FakeAdcsTransport();
        using var ca = Ca(transport);

        var nameless = Request() with
        {
            Subject = new CardholderIdentity("Jan Nowak", "jnowak@blinky.lab", "S-1-5-21-1-2-3-1104", null),
        };

        var refusal = await Assert.ThrowsAsync<IssuancePolicyException>(() => ca.IssueAsync(nameless));

        Assert.Contains("sAMAccountName", refusal.Message, StringComparison.Ordinal);
        Assert.Equal(0, transport.Submissions);
    }

    [Fact]
    public async Task An_issuance_sends_a_cmc_and_names_the_template_in_the_attributes()
    {
        var transport = new FakeAdcsTransport();
        using var ca = Ca(transport);

        await ca.IssueAsync(Request());

        Assert.Equal(AdcsRequestFormat.Cmc, transport.LastFormat);
        Assert.Equal("CertificateTemplate:BlinkySmartcardUser", transport.LastAttributes);

        // And what went over the wire is a CMC rather than the bare PKCS#10:
        // without the enrolment agent's signature the CA has no evidence of who
        // was allowed to ask on somebody else's behalf.
        Assert.NotNull(transport.LastRequest);
        Assert.NotEqual(Request().Pkcs10.Length, transport.LastRequest!.Length);
    }

    [Fact]
    public async Task An_issued_certificate_comes_back_with_its_chain_leaf_first()
    {
        using var issuer = AdcsTestCertificates.Issued("CN=lab issuing ca");
        using var leaf = AdcsTestCertificates.Issued();

        var transport = new FakeAdcsTransport { Certificate = leaf, ChainWith = issuer };
        using var ca = Ca(transport);

        var issued = await ca.IssueAsync(Request());

        Assert.Equal(leaf.Thumbprint, issued.Certificate.Thumbprint);

        // Issuer first, anchor last - the same order the built-in CA returns, so
        // that a caller writing a chain to a card need not ask which backend
        // produced it.
        Assert.Equal(2, issued.Chain.Count);
        Assert.Equal(leaf.Thumbprint, issued.Chain[0].Thumbprint);
        Assert.Equal(issuer.Thumbprint, issued.Chain[1].Thumbprint);
    }

    [Fact]
    public async Task A_ca_that_sent_no_chain_still_yields_the_certificate()
    {
        using var leaf = AdcsTestCertificates.Issued();

        using var ca = Ca(new FakeAdcsTransport { Certificate = leaf, ChainWith = null });

        var issued = await ca.IssueAsync(Request());

        // A missing chain is a trust-store problem at the workstation, not a
        // reason to throw away a certificate somebody's card is waiting for.
        Assert.Equal(leaf.Thumbprint, Assert.Single(issued.Chain).Thumbprint);
    }

    [Fact]
    public async Task A_denial_is_a_policy_refusal_carrying_the_cas_own_words()
    {
        using var ca = Ca(new FakeAdcsTransport
        {
            Disposition = AdcsDisposition.Denied,
            StatusMessage = "Denied by Policy Module: The permissions on the certificate "
                + "template do not allow the current user to enroll for this type of certificate.",
            HResult = unchecked((int)0x80094012),
        });

        var refusal = await Assert.ThrowsAsync<IssuancePolicyException>(
            () => ca.IssueAsync(Request()));

        // Somebody asked for something they may not have, which is a different
        // thing from a fault - and the CA named which rule it was, so that text
        // is worth more than anything this code could write instead.
        Assert.Contains("do not allow the current user", refusal.Message, StringComparison.Ordinal);
        Assert.Contains("0x80094012", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_request_waiting_for_a_certificate_manager_is_neither_success_nor_failure()
    {
        using var ca = Ca(new FakeAdcsTransport
        {
            Disposition = AdcsDisposition.UnderSubmission,
            RequestId = 4711,
            StatusMessage = "Taken Under Submission",
        });

        var pending = await Assert.ThrowsAsync<IssuancePendingException>(
            () => ca.IssueAsync(Request()));

        // The request is alive at the CA and becomes a certificate if somebody
        // approves it. Losing the id would lose the certificate.
        Assert.Equal(4711, pending.RequestId);
        Assert.IsAssignableFrom<CertificateAuthorityException>(pending);
        Assert.IsNotType<IssuancePolicyException>(pending);
    }

    [Fact]
    public async Task Issued_with_no_certificate_attached_names_the_request_id_to_look_up()
    {
        using var ca = Ca(new FakeAdcsTransport { Certificate = null, RequestId = 99 });

        var failure = await Assert.ThrowsAsync<CertificateAuthorityException>(
            () => ca.IssueAsync(Request()));

        Assert.Contains("99", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Revoking_reaches_the_ca_with_the_reason_code_the_crl_uses()
    {
        var transport = new FakeAdcsTransport();
        using var ca = Ca(transport);

        await ca.RevokeAsync(new RevocationRequest("1a2b3c", Blinky.Pki.X509RevocationReason.KeyCompromise));

        Assert.Equal("1a2b3c", transport.LastSerial);
        Assert.Equal(1, transport.LastReason);
    }

    [Fact]
    public async Task A_deployment_with_revocation_switched_off_refuses_rather_than_pretends()
    {
        var transport = new FakeAdcsTransport();
        using var ca = Ca(transport, new AdcsCaOptions(AllowRevocation: false));

        var refusal = await Assert.ThrowsAsync<IssuancePolicyException>(
            () => ca.RevokeAsync(new RevocationRequest("1a2b3c", Blinky.Pki.X509RevocationReason.Superseded)));

        // Believing a certificate is revoked while the CA keeps listing it as
        // valid is worse than refusing.
        Assert.Contains("revocation switched off", refusal.Message, StringComparison.Ordinal);
        Assert.Null(transport.LastSerial);
    }

    [Fact]
    public async Task A_revocation_the_ca_did_not_perform_says_which_grant_is_missing()
    {
        using var ca = Ca(new FakeAdcsTransport
        {
            Revoked = false,
            StatusMessage = "Access is denied.",
        });

        var failure = await Assert.ThrowsAsync<CertificateAuthorityException>(
            () => ca.RevokeAsync(new RevocationRequest("1a2b3c", Blinky.Pki.X509RevocationReason.Superseded)));

        Assert.Contains("Access is denied.", failure.Message, StringComparison.Ordinal);
        Assert.Contains("separate grant", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task There_is_no_revocation_list_to_hand_out()
    {
        using var ca = Ca(new FakeAdcsTransport());

        Assert.Null(await ca.GetCrlAsync());
    }
}

/// <summary>
/// A Microsoft CA's answers, without a Microsoft CA.
/// </summary>
/// <remarks>
/// Returns the dispositions ADCS actually returns rather than a success and a
/// failure, because three of the seven are neither and the interesting decisions
/// are all about those.
/// </remarks>
internal sealed class FakeAdcsTransport : IAdcsTransport
{
    public string Description => "stub";

    public bool AdminAvailable { get; init; } = true;

    public AdcsDisposition Disposition { get; init; } = AdcsDisposition.Issued;

    public int RequestId { get; init; } = 1;

    public string? StatusMessage { get; init; }

    public int? HResult { get; init; }

    public bool Revoked { get; init; } = true;

    /// <summary>What the CA issued. Null means it claimed success and sent none.</summary>
    public X509Certificate2? Certificate { get; init; } = AdcsTestCertificates.Issued();

    /// <summary>An issuer to put in the PKCS#7 beside the leaf, or none.</summary>
    public X509Certificate2? ChainWith { get; init; }

    public int Submissions { get; private set; }

    public byte[]? LastRequest { get; private set; }

    public AdcsRequestFormat? LastFormat { get; private set; }

    public string? LastAttributes { get; private set; }

    public string? LastSerial { get; private set; }

    public int? LastReason { get; private set; }

    public Task<AdcsDescribeResponse> DescribeAsync(CancellationToken ct = default) =>
        DescribeFault is not null
            ? Task.FromException<AdcsDescribeResponse>(DescribeFault)
            : Task.FromResult(new AdcsDescribeResponse(
                AdcsTransport.SchemaVersion, "stub", "CA01\\Lab Issuing CA", "Lab Issuing CA",
                AdminAvailable, CertificateChain: CaChain, Templates: PublishedTemplates));

    public Task<AdcsSubmitResponse> SubmitAsync(
        byte[] request, AdcsRequestFormat format, string? attributes, CancellationToken ct = default)
    {
        Submissions++;
        LastRequest = request;
        LastFormat = format;
        LastAttributes = attributes;

        return Task.FromResult(Answer());
    }

    public Task<AdcsSubmitResponse> RetrieveAsync(int requestId, CancellationToken ct = default) =>
        Task.FromResult(Answer());

    public IReadOnlyList<string>? PublishedTemplates { get; init; } = ["BlinkySmartcardUser"];

    public Dictionary<string, AdcsTemplateInfo> TemplateObjects { get; } = new(StringComparer.Ordinal);

    public Exception? DescribeFault { get; init; }

    /// <summary>What a CA that exists hands over. Null is a CA that did not answer.</summary>
    public string? CaChain { get; init; } = "MIIBAA==";

    public Task<AdcsTemplateInfo> DescribeTemplateAsync(string name, CancellationToken ct = default) =>
        Task.FromResult(TemplateObjects.TryGetValue(name, out var info)
            ? info
            : new AdcsTemplateInfo(name, Found: false, Account: "LAB\\svc-blinky"));

    public Task<AdcsRevokeResponse> RevokeAsync(
        string serialNumber, int reason, DateTimeOffset? effectiveAt, CancellationToken ct = default)
    {
        LastSerial = serialNumber;
        LastReason = reason;

        return Task.FromResult(new AdcsRevokeResponse(Revoked, StatusMessage));
    }

    private AdcsSubmitResponse Answer() => new(
        Disposition,
        RequestId,
        Certificate is null ? null : Convert.ToBase64String(Certificate.RawData),
        Chain(),
        StatusMessage,
        HResult);

    private string? Chain()
    {
        if (Certificate is null || ChainWith is null)
        {
            return null;
        }

        // Certs-only PKCS#7, which is what CR_OUT_CHAIN produces.
        var collection = new X509Certificate2Collection { Certificate, ChainWith };

        return Convert.ToBase64String(collection.Export(X509ContentType.Pkcs7)!);
    }
}
