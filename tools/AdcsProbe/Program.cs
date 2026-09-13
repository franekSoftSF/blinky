// Blinky - ADCS connector probe.
//
// Asks a Blinky.AdcsConnector what it is in front of, over the same transport
// the API uses, with the same pinning and the same version check. Read-only
// unless --submit or --revoke is given; --retrieve only reads.
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
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

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
var revoke = arguments.GetValueOrDefault("revoke");
var retrieve = arguments.GetValueOrDefault("retrieve");
var subject = arguments.GetValueOrDefault("subject", "CN=probe");
var requester = arguments.GetValueOrDefault("requester");
var keyAlgorithm = arguments.GetValueOrDefault("key", "ECCP256");
var queueUrl = arguments.GetValueOrDefault("queue");

if (queueUrl is null && (connector is null || clientPath is null))
{
    Console.Error.WriteLine(
        "usage: --connector https://host:8444 --client <p12> [--client-password ...]\n"
        + "       (--fingerprint <sha256> | --server-ca <pem-or-der>)\n"
        + "       [--ca-config 'HOST\\CA name'] [--submit <template> --requester 'DOMAIN\\user'\n"
        + "        (--remote-agent | --agent <p12> --agent-password ...)]\n"
        + "       [--check <template> [--remote-agent]] [--key ECCP256|RSA2048]\n"
        + "       [--revoke <serial> [--reason CessationOfOperation]] [--retrieve <request id>]\n"
        + "   or: --queue https://127.0.0.1:19443 --queue-certificate <p12> [--queue-password ...]\n"
        + "       --connector-fingerprint <sha256>   (the connector dials this probe instead)");

    return 2;
}

try
{
    // --queue: this probe plays the API's half of a connector that dials in, with the
    // same queue and the same transport the API uses, so the connector's polling mode
    // can be run against a real CA before an API with it is deployed anywhere.
    var queue = queueUrl is null ? null : new ConnectorQueue();

    await using var host = queue is null
        ? null
        : await QueueHost.StartAsync(
            queueUrl!,
            arguments.GetValueOrDefault("queue-certificate") ?? throw new ArgumentException("--queue needs --queue-certificate"),
            arguments.GetValueOrDefault("queue-password"),
            arguments.GetValueOrDefault("connector-fingerprint") ?? throw new ArgumentException("--queue needs --connector-fingerprint"),
            queue);

    connector ??= "the connector polling this probe";

    using var transport = queue is null
        ? new ConnectorAdcsTransport(new ConnectorTransportOptions(
            new Uri(connector), clientPath, clientPassword, fingerprint, serverCa, caConfig))
        : new ConnectorAdcsTransport(queue, caConfig);

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

    if (revoke is not null)
    {
        // Through the same class the API revokes with, so a refusal reads the way
        // an operator would see it. Cessation of operation by default: a test
        // certificate whose key was thrown away was not compromised.
        using var revokingCa = new AdcsCertificateAuthority("probe", transport, (IEnrolmentAgentSource?)null);

        var reason = Enum.Parse<Blinky.Pki.X509RevocationReason>(
            arguments.GetValueOrDefault("reason", nameof(Blinky.Pki.X509RevocationReason.CessationOfOperation)),
            ignoreCase: true);

        Console.WriteLine();
        Console.WriteLine($"revoking    {revoke} at the CA, reason {reason}. This cannot be undone.");

        await revokingCa.RevokeAsync(new RevocationRequest(revoke, reason));

        Console.WriteLine("revoked     the CA accepted it; it is on the next CRL the CA publishes");

        return 0;
    }

    if (retrieve is not null)
    {
        // Read-only. An ADCS serial number ends in the request id, so a certificate
        // somebody holds the serial of can be read back without issuing another.
        var answer = await transport.RetrieveAsync(int.Parse(retrieve, System.Globalization.CultureInfo.InvariantCulture));

        Console.WriteLine();
        Console.WriteLine($"request     {answer.RequestId}: {answer.Disposition}"
            + (answer.StatusMessage is { Length: > 0 } status ? $" - {status}" : string.Empty));

        if (answer.Certificate is { Length: > 0 } der)
        {
            using var retrieved = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(der));
            Describe(retrieved);
        }

        return 0;
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

    var issued = await ca.IssueAsync(Context(subject, requester, template, keyAlgorithm));

    Console.WriteLine();
    Console.WriteLine($"chain       {issued.Chain.Count} certificate(s)");
    Describe(issued.Certificate);

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
/// What ADCS put in, which is not what the request asked for: the subject and the UPN
/// come from the directory object the requester name points at, and the key usage from
/// the template - and a certificate allowed only key agreement logs nobody on.
/// </summary>
static void Describe(X509Certificate2 certificate)
{
    Console.WriteLine($"issued      {certificate.Subject}");
    Console.WriteLine($"serial      {certificate.SerialNumber}");
    Console.WriteLine($"key         {certificate.PublicKey.Oid.FriendlyName ?? certificate.PublicKey.Oid.Value}");

    foreach (var extension in certificate.Extensions)
    {
        if (extension.Oid?.Value is "2.5.29.15" or "2.5.29.37" or "2.5.29.17" or "1.3.6.1.4.1.311.25.2")
        {
            Console.WriteLine($"{extension.Oid.Value,-11} {extension.Format(false)}");
        }
    }
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
/// <remarks>
/// ECCP256 by default because that is what a card is issued with. RSA2048 exists
/// because a template left on the default cryptography - a legacy CSP, RSA, 2048
/// bits minimum - refuses a P-256 key as too short, which is how HZCS01's first
/// submission ended: CERTSRV_E_KEY_LENGTH, after the CA had read the CMC.
/// </remarks>
static CertificateRequestContext Context(
    string subject, string? requester, string template, string algorithm)
{
    using AsymmetricAlgorithm key = algorithm.ToUpperInvariant() switch
    {
        "ECCP256" => ECDsa.Create(ECCurve.NamedCurves.nistP256),
        "RSA2048" => RSA.Create(2048),
        _ => throw new ArgumentException($"--key {algorithm} is neither ECCP256 nor RSA2048."),
    };

    var request = key is RSA rsa
        ? new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
        : new CertificateRequest(subject, (ECDsa)key, HashAlgorithmName.SHA256);

    return new CertificateRequestContext(
        request.CreateSigningRequest(),
        new AttestedKey(0, "9A", key.ExportSubjectPublicKeyInfo(), null, null),
        new CardholderIdentity(subject, null, null, null, requester),
        new IssuanceProfile(
            "probe", "9A", algorithm.ToUpperInvariant(), 365,
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

/// <summary>The API's two connector routes, over the same queue, with a fingerprint for a gate.</summary>
internal static class QueueHost
{
    public static async Task<Microsoft.AspNetCore.Builder.WebApplication> StartAsync(
        string url, string certificatePath, string? password, string connectorFingerprint, ConnectorQueue queue)
    {
        var wanted = string.Concat(connectorFingerprint.Where(char.IsAsciiHexDigit)).ToUpperInvariant();
        var certificate = X509CertificateLoader.LoadPkcs12FromFile(certificatePath, password);

        var builder = Microsoft.AspNetCore.Builder.WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls(url);
        builder.WebHost.ConfigureKestrel(kestrel => kestrel.ConfigureHttpsDefaults(https =>
        {
            https.ServerCertificate = certificate;
            https.ClientCertificateMode = Microsoft.AspNetCore.Server.Kestrel.Https.ClientCertificateMode.RequireCertificate;
            https.ClientCertificateValidation = (_, _, _) => true;
        }));

        var app = builder.Build();

        app.Use(async (context, next) =>
        {
            var presented = await context.Connection.GetClientCertificateAsync();
            var seen = presented?.GetCertHashString(HashAlgorithmName.SHA256);

            if (seen != wanted)
            {
                Console.Error.WriteLine($"queue       refused a poll from {seen ?? "no certificate"}");
                context.Response.StatusCode = 401;
                return;
            }

            await next();
        });

        app.MapGet(AdcsQueue.NextPath, async (int? wait, CancellationToken ct) =>
        {
            var item = await queue.NextAsync(
                TimeSpan.FromSeconds(Math.Clamp(wait ?? AdcsQueue.MaximumWaitSeconds, 1, AdcsQueue.MaximumWaitSeconds)), ct);

            if (item is not null)
            {
                Console.WriteLine($"queue       handed out {item.Method} {item.Path.Split('?')[0]}");
            }

            return item is null ? Results.NoContent() : Results.Ok(item);
        });

        app.MapPost(AdcsQueue.ResultPath, (AdcsWorkResult result) =>
            queue.Complete(result) ? Results.NoContent() : Results.StatusCode(410));

        await app.StartAsync();

        Console.WriteLine($"queue       listening on {url} for connector {wanted[..16]}...");

        return app;
    }
}
