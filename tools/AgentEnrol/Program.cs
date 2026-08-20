// Blinky - agent enrolment tool.
//
// Does what Blinky.Agent.Service will do on first start: generate a key pair,
// ask the backend for a certificate with the deployment's bootstrap token, and
// then prove the certificate works by calling an authenticated endpoint with
// it.
//
//     dotnet run --project tools/AgentEnrol -- \
//         --backend https://localhost:9443 --hostname ws01 --domain corp.example \
//         --token <bootstrap> --out certs/agent --insecure
//
// It exists ahead of the agent itself because enrolment is the one flow that
// cannot be tested with a certificate already in hand, and because a shell
// script doing this would have to parse JSON and juggle PEM by hand.

using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Serialization;

var arguments = ParseArguments(args);

var backend = arguments.GetValueOrDefault("backend", "https://localhost:9443");
var hostname = arguments.GetValueOrDefault("hostname", Environment.MachineName);
var domain = arguments.GetValueOrDefault("domain");
var token = arguments.GetValueOrDefault("token");
var outputPrefix = arguments.GetValueOrDefault("out", "certs/agent");
var insecure = arguments.ContainsKey("insecure");

if (string.IsNullOrWhiteSpace(domain) || string.IsNullOrWhiteSpace(token))
{
    Console.Error.WriteLine("--domain and --token are required.");
    Console.Error.WriteLine(
        "The domain is not derived from the machine: the agent runs as LocalSystem, "
        + "whose UserDomainName is the machine name, and guessing produces a second "
        + "orphaned agent row.");
    return 2;
}

using var handler = new HttpClientHandler();
if (insecure)
{
    // Development certificates from scripts/dev-certs.sh are self-signed.
    handler.ServerCertificateCustomValidationCallback =
        HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
}

using var http = new HttpClient(handler) { BaseAddress = new Uri(backend) };

// A fresh key per enrolment. The private key never leaves this machine; only
// the request travels, and it is signed by that key, which is what makes it
// proof of possession rather than a claim.
using var key = RSA.Create(3072);
var subject = new X500DistinguishedName($"CN={hostname}.{domain}");
var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256,
    RSASignaturePadding.Pkcs1);

var csrPem = request.CreateSigningRequestPem();

Console.WriteLine($"enrolling {hostname}.{domain} with {backend}");

var response = await http.PostAsJsonAsync("/api/agents/enroll", new
{
    hostname,
    domain,
    bootstrapToken = token,
    certificateSigningRequest = csrPem,
});

if (!response.IsSuccessStatusCode)
{
    Console.Error.WriteLine(
        $"enrolment refused: {(int)response.StatusCode} {await response.Content.ReadAsStringAsync()}");
    return 1;
}

var enrolment = await response.Content.ReadFromJsonAsync<EnrolmentResponse>();
if (enrolment is null)
{
    Console.Error.WriteLine("enrolment returned no body");
    return 1;
}

Console.WriteLine($"  agent id     {enrolment.AgentId}");
Console.WriteLine($"  issued by    {enrolment.IssuerSubject}");
Console.WriteLine($"  valid until  {enrolment.NotAfter:yyyy-MM-dd}");
Console.WriteLine($"  already known {enrolment.AlreadyRegistered}");

Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(outputPrefix)) ?? ".");
await File.WriteAllTextAsync($"{outputPrefix}.crt", enrolment.CertificatePem);
await File.WriteAllTextAsync($"{outputPrefix}.key", key.ExportPkcs8PrivateKeyPem());

// Prove the certificate is usable, rather than assuming a 200 meant success.
using var identity = X509Certificate2.CreateFromPem(enrolment.CertificatePem)
    .CopyWithPrivateKey(key);

using var authenticatedHandler = new HttpClientHandler();
authenticatedHandler.ClientCertificates.Add(
    X509CertificateLoader.LoadPkcs12(identity.Export(X509ContentType.Pkcs12), null));

if (insecure)
{
    authenticatedHandler.ServerCertificateCustomValidationCallback =
        HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
}

using var authenticated = new HttpClient(authenticatedHandler) { BaseAddress = new Uri(backend) };

var whoami = await authenticated.GetAsync("/api/agents/whoami");
if (!whoami.IsSuccessStatusCode)
{
    Console.Error.WriteLine(
        $"the issued certificate was refused: {(int)whoami.StatusCode} "
        + await whoami.Content.ReadAsStringAsync());
    return 1;
}

Console.WriteLine($"  whoami       {await whoami.Content.ReadAsStringAsync()}");

var heartbeat = await authenticated.PostAsJsonAsync(
    $"/api/agents/{enrolment.AgentId}/heartbeat", new { version = "0.1.0-tool" });

if (!heartbeat.IsSuccessStatusCode)
{
    Console.Error.WriteLine($"heartbeat refused: {(int)heartbeat.StatusCode}");
    return 1;
}

Console.WriteLine($"  heartbeat    {await heartbeat.Content.ReadAsStringAsync()}");
Console.WriteLine($"enrolled: {enrolment.AgentId}");

return 0;

static Dictionary<string, string> ParseArguments(string[] args)
{
    var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    for (var i = 0; i < args.Length; i++)
    {
        if (!args[i].StartsWith("--", StringComparison.Ordinal))
        {
            continue;
        }

        var name = args[i][2..];
        var hasValue = i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal);

        result[name] = hasValue ? args[++i] : "true";
    }

    return result;
}

internal sealed record EnrolmentResponse(
    [property: JsonPropertyName("agentId")] Guid AgentId,
    [property: JsonPropertyName("certificatePem")] string CertificatePem,
    [property: JsonPropertyName("issuerSubject")] string IssuerSubject,
    [property: JsonPropertyName("notAfter")] DateTimeOffset NotAfter,
    [property: JsonPropertyName("alreadyRegistered")] bool AlreadyRegistered);
