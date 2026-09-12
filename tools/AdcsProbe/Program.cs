// Blinky - ADCS connector probe.
//
// Asks a Blinky.AdcsConnector what it is in front of, over the same transport
// the API uses, with the same pinning and the same version check. Read-only
// unless --submit is given.
//
//     dotnet run --project tools/AdcsProbe -- \
//         --connector https://ca01.blinky.lab:8444 \
//         --client certs/adcs-client.p12 --client-password ... \
//         --fingerprint <sha256 of the connector's TLS certificate>
//
// It exists because everything between the container and ICertRequest3 can be
// wrong in ways that look identical from the API: a fingerprint that does not
// match, a client certificate the connector was not told about, a firewall
// rule, a connector nobody upgraded, a service account without Enroll. Each of
// those has its own sentence here, and none of them needs a card or a database.
//
// --submit asks a real CA for a real certificate on behalf of a real person,
// signed by the enrolment agent the connector holds (--remote-agent) or by one
// in a local file (--agent).
// It is behind a flag for the same reason the PIV probes are read-only.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Blinky.Contracts;
using Blinky.Domain;
using Blinky.Pki;
using Blinky.Pki.Adcs;

var arguments = ParseArguments(args);

var connector = arguments.GetValueOrDefault("connector");
var clientPath = arguments.GetValueOrDefault("client");
var clientPassword = arguments.GetValueOrDefault("client-password");
var fingerprint = arguments.GetValueOrDefault("fingerprint");
var serverCa = arguments.GetValueOrDefault("server-ca");
var caConfig = arguments.GetValueOrDefault("ca-config");
var template = arguments.GetValueOrDefault("submit");
var agentPath = arguments.GetValueOrDefault("agent");
var agentPassword = arguments.GetValueOrDefault("agent-password");
var remoteAgent = arguments.ContainsKey("remote-agent");
var check = arguments.GetValueOrDefault("check");
var subject = arguments.GetValueOrDefault("subject", "CN=probe");

if (connector is null || clientPath is null)
{
    Console.Error.WriteLine(
        "usage: --connector https://host:8444 --client <p12> [--client-password ...]\n"
        + "       (--fingerprint <sha256> | --server-ca <pem-or-der>)\n"
        + "       [--ca-config 'HOST\\CA name'] [--submit <template> --subject 'CN=...'\n"
        + "        (--remote-agent | --agent <p12> --agent-password ...)]\n"
        + "       [--check <template> [--remote-agent]]");

    return 2;
}

var options = new ConnectorTransportOptions(
    new Uri(connector),
    clientPath,
    clientPassword,
    fingerprint,
    serverCa,
    caConfig);

try
{
    using var transport = new ConnectorAdcsTransport(options);

    Console.WriteLine($"transport   {transport.Description}");

    var described = await transport.DescribeAsync();

    Console.WriteLine($"connector   {described.ConnectorVersion}, schema {described.SchemaVersion}");
    Console.WriteLine($"ca          {described.CaConfig}");
    // The wire carries a bool, so this cannot say which of the two it was: the
    // service account without Issue and Manage Certificates, or a machine with
    // certcli.dll and no certadm.dll. Both are real and both mean the same thing
    // to a caller. The connector's own log says which.
    Console.WriteLine($"revocation  {(described.AdminAvailable
        ? "available - the account may manage certificates"
        : "NOT available - no Issue and Manage Certificates, or no ICertAdmin2 on that machine")}");

    if (described.CertificateChain is { Length: > 0 } chain)
    {
        Console.WriteLine($"ca chain    {Convert.FromBase64String(chain).Length} bytes");
    }

    Console.WriteLine(described.Templates is { Count: > 0 } templates
        ? "templates   " + string.Join(", ", templates)
        : "templates   not established - which is not the same as none");

    if (described.EnrolmentAgent is { } held)
    {
        var custody = ConnectorEnrolmentAgentKeyStore.CustodyOf(held);

        Console.WriteLine($"agent       {held.Source}, {held.Provider ?? "provider not named"}");
        Console.WriteLine($"            exportable: {held.Exportable?.ToString() ?? "not said"}, "
            + $"production-ready: {custody.ProductionReady}");
    }
    else
    {
        Console.WriteLine("agent       none held by this connector");
    }

    if (check is not null)
    {
        // The registration check the API runs, against the template named here
        // for the smart-card profile. Read-only: it asks the CA, reads the
        // template out of the directory and opens the agent, and submits nothing.
        using var checkedCa = new AdcsCertificateAuthority(
            "probe",
            transport,
            remoteAgent ? new ConnectorEnrolmentAgentSource(transport, connector) : null,
            new AdcsCaOptions(TemplateMap: new Dictionary<string, string> { ["smartcard-logon"] = check }));

        var report = await checkedCa.CheckRegistrationAsync();

        Console.WriteLine();
        Console.WriteLine($"registration {report.Outcome.ToString().ToUpperInvariant()}");

        foreach (var finding in report.Findings)
        {
            Console.WriteLine($"  {finding.Severity,-8} {finding.Code}");
            Console.WriteLine($"           {finding.Message}");
        }

        return report.Outcome switch
        {
            RegistrationOutcome.Accepted => 0,
            RegistrationOutcome.Unverified => 5,
            _ => 4,
        };
    }

    if (template is null)
    {
        return 0;
    }

    if (agentPath is null && !remoteAgent)
    {
        Console.Error.WriteLine(
            "--submit needs --remote-agent, or --agent for a key in a file here: a CMC without an "
            + "enrolment agent's signature is a request ADCS will refuse, and sending one would "
            + "only prove that.");

        return 2;
    }

    Console.WriteLine();
    Console.WriteLine(
        $"submitting a request for {subject} against {template}. This asks a real CA for a "
        + "real certificate.");

    using IEnrolmentAgentKeyStore agent = remoteAgent
        ? await ConnectorEnrolmentAgentKeyStore.OpenAsync(transport, connector)
        : FileEnrolmentAgentKeyStore.Open(agentPath!, agentPassword, allowFileKeys: true);

    Console.WriteLine($"agent       {agent.Certificate.Subject}");
    Console.WriteLine($"            {agent.Custody.Detail}");

    using var ca = new AdcsCertificateAuthority("probe", transport, agent);

    var issued = await ca.IssueAsync(Context(subject, template));

    Console.WriteLine();
    Console.WriteLine($"issued      {issued.Certificate.Subject}");
    Console.WriteLine($"serial      {issued.SerialNumber}");
    Console.WriteLine($"chain       {issued.Chain.Count} certificate(s)");

    return 0;
}
catch (IssuancePendingException pending)
{
    // Not a failure. A certificate manager has to approve it, and the number is
    // how it gets collected afterwards.
    Console.Error.WriteLine($"pending     {pending.Message}");
    Console.Error.WriteLine($"request id  {pending.RequestId}");

    return 3;
}
catch (CertificateAuthorityException ex)
{
    Console.Error.WriteLine($"refused     {ex.Message}");

    return 1;
}

/// <summary>
/// A request context of the shape the API assembles, with a key generated here.
/// </summary>
/// <remarks>
/// The attestation is filled in with something plausible and is not used by this
/// backend: ADCS never sees it, because the CA's evidence is the enrolment
/// agent's signature. A probe that pretended to attest would be claiming
/// something about hardware that is not present.
/// </remarks>
static CertificateRequestContext Context(string subject, string template)
{
    using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    var pkcs10 = new CertificateRequest(subject, key, HashAlgorithmName.SHA256)
        .CreateSigningRequest();

    return new CertificateRequestContext(
        pkcs10,
        new AttestedKey(0, "9A", key.ExportSubjectPublicKeyInfo(), null, null),
        new CardholderIdentity(subject, null, null, null),
        new IssuanceProfile(
            "probe", "9A", "ECCP256", 365,
            ["1.3.6.1.5.5.7.3.2"],
            IncludeUpnSan: false,
            IncludeSidExtension: false,
            AdcsTemplateName: template));
}

static Dictionary<string, string> ParseArguments(string[] args)
{
    var parsed = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    for (var index = 0; index < args.Length; index++)
    {
        if (!args[index].StartsWith("--", StringComparison.Ordinal))
        {
            continue;
        }

        var name = args[index][2..];
        var value = index + 1 < args.Length
                    && !args[index + 1].StartsWith("--", StringComparison.Ordinal)
            ? args[++index]
            : string.Empty;

        parsed[name] = value;
    }

    return parsed;
}
