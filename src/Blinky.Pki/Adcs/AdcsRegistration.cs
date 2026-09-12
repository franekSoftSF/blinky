using Blinky.Contracts;

namespace Blinky.Pki.Adcs;

/// <summary>
/// Whether a finding stops a Microsoft CA being used, or is worth knowing.
/// </summary>
public enum RegistrationSeverity
{
    /// <summary>Enrolment will fail, or will succeed and produce the wrong thing.</summary>
    Refusal,

    /// <summary>
    /// Enrolment will work, and something about the arrangement is weaker than it
    /// should be.
    /// </summary>
    Warning,

    /// <summary>
    /// Something could not be established. Not a refusal, because an estate that
    /// restricts reading must not have correct templates refused - and not a pass,
    /// which is what counting only refusals made of it at first.
    /// </summary>
    Unknown,
}

public enum RegistrationOutcome
{
    /// <summary>Nothing refused and nothing left unestablished.</summary>
    Accepted,

    /// <summary>Nothing refused, and something could not be checked.</summary>
    Unverified,

    Refused,
}

/// <param name="Code">Stable, for the console to key on. The message is for a person.</param>
public sealed record RegistrationFinding(string Code, RegistrationSeverity Severity, string Message);

/// <remarks>
/// Three outcomes rather than a bool. The first run against a connector on a machine
/// with no CA and no domain reported "accepted": the template could not be read and
/// the CA did not exist, and neither was a refusal, so a check that only counted
/// refusals passed a registration in which nothing had been verified.
/// </remarks>
public sealed record RegistrationReport(string CaName, IReadOnlyList<RegistrationFinding> Findings)
{
    public RegistrationOutcome Outcome =>
        Findings.Any(finding => finding.Severity == RegistrationSeverity.Refusal)
            ? RegistrationOutcome.Refused
            : Findings.Any(finding => finding.Severity == RegistrationSeverity.Unknown)
                ? RegistrationOutcome.Unverified
                : RegistrationOutcome.Accepted;

    public bool Accepted => Outcome == RegistrationOutcome.Accepted;
}

/// <summary>
/// Everything about a Microsoft CA that can be found wrong before anybody enrols -
/// patch 0033.
/// </summary>
/// <remarks>
/// <para>
/// Each refusal is a way enrolment fails at somebody's desk, or worse succeeds:
/// a template that takes the subject from the request issues certificates without
/// the SID extension, and a domain controller will not log anybody in with them.
/// Finding that at registration is the difference between a sentence in the console
/// and a support call from a person holding a card that does not work.
/// </para>
/// <para>
/// <b>Unknown is its own severity, never a refusal and never a pass.</b> An estate that
/// restricts read access to the Configuration partition must not have correct
/// templates refused, and must not have broken ones reported as fine.
/// </para>
/// </remarks>
public static class AdcsRegistration
{
    /// <summary>msPKI-Certificate-Name-Flag: CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT.</summary>
    public const int EnrolleeSuppliesSubject = 0x1;

    public const string CertificateRequestAgent = "1.3.6.1.4.1.311.20.2.1";

    public static async Task<RegistrationReport> CheckAsync(
        string caName,
        IAdcsTransport transport,
        IEnrolmentAgentSource? agents,
        AdcsCaOptions settings,
        CancellationToken ct = default)
    {
        var findings = new List<RegistrationFinding>();

        AdcsDescribeResponse described;
        try
        {
            described = await transport.DescribeAsync(ct);
        }
        catch (CertificateAuthorityException ex)
        {
            // Nothing else can be checked without the CA, and listing a dozen
            // unknowns under an unreachable connector would bury the one finding
            // that matters.
            findings.Add(new("ca-unreachable", RegistrationSeverity.Refusal, ex.Message));

            return new RegistrationReport(caName, findings);
        }

        if (described.CertificateChain is not { Length: > 0 })
        {
            // A CA hands its own certificate to anybody allowed to talk to it.
            // Not getting it is how a config string naming a CA that does not
            // exist looks from here - the connector answered, the CA behind it
            // did not - and the first run of this check on a machine with no CA
            // reported the registration as fine because nothing else noticed.
            findings.Add(new(
                "ca-certificate-unavailable",
                RegistrationSeverity.Unknown,
                $"{caName} did not hand over its own certificate through the connector. The config "
                + $"string {described.CaConfig} may name a CA that is not there, or DCOM to it is "
                + "blocked; the connector's log has the error."));
        }

        if (agents is not null)
        {
            await CheckAgent(agents, findings, ct);
        }

        if (settings.AllowRevocation && !described.AdminAvailable)
        {
            findings.Add(new(
                "revocation-unavailable",
                RegistrationSeverity.Warning,
                $"{caName} did not let the connector's account manage certificates, so revoking "
                + "in Blinky will not revoke at the CA. That needs Issue and Manage Certificates, "
                + "confined by certificate manager restrictions rather than granted CA-wide - or "
                + "the connector's machine has no ICertAdmin2 at all; its log says which."));
        }

        await CheckTemplates(caName, transport, described, settings, findings, ct);

        return new RegistrationReport(caName, findings);
    }

    private static async Task CheckAgent(
        IEnrolmentAgentSource agents, List<RegistrationFinding> findings, CancellationToken ct)
    {
        try
        {
            var agent = await agents.OpenAsync(ct);

            if (!agent.Custody.ProductionReady)
            {
                findings.Add(new("agent-custody", RegistrationSeverity.Warning, agent.Custody.Detail));
            }
        }
        catch (CertificateAuthorityException ex)
        {
            // Missing, expired, or not an enrolment agent: every one is a refusal,
            // because ADCS will not proceed without a valid one and there is no
            // configuration that turns the requirement off.
            findings.Add(new("agent-unusable", RegistrationSeverity.Refusal, ex.Message));
        }
    }

    private static async Task CheckTemplates(
        string caName, IAdcsTransport transport, AdcsDescribeResponse described,
        AdcsCaOptions settings, List<RegistrationFinding> findings, CancellationToken ct)
    {
        if (settings.Templates.Count == 0)
        {
            findings.Add(new(
                "no-template",
                RegistrationSeverity.Refusal,
                $"No profile is mapped to a template on {caName}, so nothing can be issued. Set "
                + "Blinky:Adcs:Templates:<profile> to a template's name."));

            return;
        }

        foreach (var (profile, template) in settings.Templates.OrderBy(pair => pair.Key, StringComparer.Ordinal))
        {
            if (string.IsNullOrWhiteSpace(template))
            {
                findings.Add(new(
                    "template-unmapped",
                    RegistrationSeverity.Refusal,
                    $"Blinky:Adcs:Templates:{profile} is empty, so the profile {profile} cannot be "
                    + $"issued from {caName}."));

                continue;
            }

            CheckPublished(caName, template, described, findings);

            AdcsTemplateInfo info;
            try
            {
                info = await transport.DescribeTemplateAsync(template, ct);
            }
            catch (CertificateAuthorityException ex)
            {
                findings.Add(new(
                    "template-unreadable",
                    RegistrationSeverity.Unknown,
                    $"The template {template} could not be read, so nothing about it has been "
                    + "checked: " + ex.Message));

                continue;
            }

            CheckTemplate(template, info, findings, settings.Algorithms);
        }
    }

    private static void CheckPublished(
        string caName, string template, AdcsDescribeResponse described, List<RegistrationFinding> findings)
    {
        if (described.Templates is null)
        {
            findings.Add(new(
                "template-publication-unknown",
                RegistrationSeverity.Unknown,
                $"Whether {caName} issues {template} could not be established. That is not the "
                + "same as it not issuing it."));
        }
        else if (!described.Templates.Contains(template, StringComparer.OrdinalIgnoreCase))
        {
            findings.Add(new(
                "template-not-published",
                RegistrationSeverity.Refusal,
                $"{caName} is not configured to issue {template}. Publish it on the CA - Certificate "
                + "Templates, New, Certificate Template to Issue. If it is published under a "
                + "different name, the name here is its display name rather than its name."));
        }
    }

    /// <summary>The template object's own faults, each in its own sentence.</summary>
    internal static void CheckTemplate(
        string template, AdcsTemplateInfo info, List<RegistrationFinding> findings,
        IReadOnlySet<string>? algorithms = null)
    {
        if (!info.Found)
        {
            findings.Add(new(
                "template-not-found",
                RegistrationSeverity.Refusal,
                $"There is no template called {template} in the forest. A template's name and its "
                + "display name differ on every template anybody has renamed, and this has to be "
                + "the name."));

            return;
        }

        if (info.NameFlags is not { } flags)
        {
            Unknown(findings, template, "name flags");
        }
        else if ((flags & EnrolleeSuppliesSubject) != 0)
        {
            findings.Add(new(
                "template-supplies-subject",
                RegistrationSeverity.Refusal,
                $"{template} takes the subject from the request. A certificate issued that way "
                + "carries no SID extension, and since KB5014754 a domain controller will not log "
                + "anybody in with it. Set the template to build the subject from Active "
                + "Directory."));
        }

        if (info.AuthorizedSignatures is not { } signatures)
        {
            Unknown(findings, template, "number of authorized signatures");
        }
        else if (signatures < 1)
        {
            findings.Add(new(
                "template-no-agent-signature",
                RegistrationSeverity.Refusal,
                $"{template} requires no authorized signature, so the CA issues on the requesting "
                + "account's own authority and the enrolment agent's signature proves nothing. Set "
                + "Issuance Requirements to one authorized signature."));
        }
        else if (info.SignaturePolicies is not { } policies)
        {
            Unknown(findings, template, "signature policy");
        }
        else if (!policies.Any(policy => policy.Contains(CertificateRequestAgent, StringComparison.Ordinal)))
        {
            // Contains rather than equals: a version 4 template encodes more than
            // OIDs into this attribute, and the policy is somewhere inside it.
            findings.Add(new(
                "template-wrong-signature-policy",
                RegistrationSeverity.Refusal,
                $"{template} requires a signature, but not one with the Certificate Request Agent "
                + $"application policy ({CertificateRequestAgent}). The CA will refuse an enrolment "
                + "agent's signature against it."));
        }

        var account = info.Account ?? "the connector's account";

        if (info.AccountMayEnroll is not { } mayEnroll)
        {
            Unknown(findings, template, $"Enroll right for {account}");
        }
        else if (!mayEnroll)
        {
            findings.Add(new(
                "account-cannot-enroll",
                RegistrationSeverity.Refusal,
                $"{account} does not hold Enroll on {template}, so the CA will deny every request. "
                + "Grant Enroll on the template's Security tab to the integration account, or to a "
                + "group it is in."));
        }

        if (algorithms is { Count: > 0 })
        {
            CheckKeys(template, info, findings, algorithms);
        }
    }

    private static void CheckKeys(
        string template, AdcsTemplateInfo info, List<RegistrationFinding> findings,
        IReadOnlySet<string> algorithms)
    {
        var ordered = algorithms.Order(StringComparer.OrdinalIgnoreCase).ToList();

        if (info.MinimalKeySize is not { } minimum)
        {
            Unknown(findings, template, "minimum key size");
        }
        else
        {
            var tooShort = ordered.Where(a => TemplateKeys.BitsOf(a) is { } bits && bits < minimum).ToList();

            if (tooShort.Count > 0)
            {
                var all = tooShort.Count == ordered.Count;

                // A refusal only when nothing this deployment enrols with gets
                // through. When some do, the CA will issue those and deny the rest,
                // and which one a card gets is chosen per enrolment.
                findings.Add(new(
                    "template-key-too-short",
                    all ? RegistrationSeverity.Refusal : RegistrationSeverity.Warning,
                    $"{template} demands keys of at least {minimum} bits, and the CA compares that "
                    + "with the key's length whatever the algorithm - a P-256 key is 256 bits. "
                    + $"Enrolments with {string.Join(", ", tooShort)} will be denied with "
                    + "CERTSRV_E_KEY_LENGTH"
                    + (all ? ", which is every algorithm this deployment enrols with. " : ". ")
                    + "Lower the minimum key size on the template's Cryptography tab, or enrol "
                    + "with a longer key."));
            }
        }

        if (TemplateKeys.AsymmetricAlgorithm(info.SignaturePolicies) is { } named)
        {
            var other = ordered.Where(a => TemplateKeys.BitsOf(a) is not null && !TemplateKeys.Matches(a, named)).ToList();

            if (other.Count > 0)
            {
                findings.Add(new(
                    "template-key-algorithm",
                    RegistrationSeverity.Warning,
                    $"{template} names {named} as its key algorithm, and this deployment also enrols "
                    + $"with {string.Join(", ", other)}. The CA does not refuse those: it enforces the "
                    + "minimum size and not the algorithm, and the lab CA issued an RSA 2048 key "
                    + "against a template naming ECDH_P256. So they will issue, with a key that is "
                    + "not the kind the template's owner chose."));
            }
        }
    }

    private static void Unknown(List<RegistrationFinding> findings, string template, string what) =>
        findings.Add(new(
            "template-attribute-unknown",
            RegistrationSeverity.Unknown,
            $"The {what} of {template} could not be read, so it has not been checked."));
}
