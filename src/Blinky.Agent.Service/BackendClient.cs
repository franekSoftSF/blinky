using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Blinky.Contracts;

namespace Blinky.Agent.Service;

/// <summary>Everything the agent says to the backend.</summary>
public sealed class BackendClient(Uri backend, bool acceptAnyServerCertificate = false)
    : IDisposable
{
    private HttpClient? authenticated;

    public Uri Backend => backend;

    /// <summary>
    /// Asks for a certificate. The private key is generated here and never
    /// leaves; only the request travels, signed by that key, which is what
    /// makes it proof of possession rather than a claim.
    /// </summary>
    public async Task<(Guid AgentId, string CertificatePem, RSA Key)> EnrolAsync(
        string hostname, string domain, string bootstrapToken, CancellationToken ct)
    {
        var key = RSA.Create(3072);
        var request = new CertificateRequest($"CN={hostname}.{domain}", key,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        using var client = CreateClient(certificate: null);

        var response = await client.PostAsJsonAsync("/api/agents/enroll", new
        {
            hostname,
            domain,
            bootstrapToken,
            certificateSigningRequest = request.CreateSigningRequestPem(),
        }, ct);

        if (!response.IsSuccessStatusCode)
        {
            key.Dispose();

            throw new InvalidOperationException(
                $"Enrolment refused: {(int)response.StatusCode} "
                + await response.Content.ReadAsStringAsync(ct));
        }

        var enrolment = await response.Content.ReadFromJsonAsync<EnrolmentResponse>(ct)
                        ?? throw new InvalidOperationException("Enrolment returned no body.");

        return (enrolment.AgentId, enrolment.CertificatePem, key);
    }

    /// <summary>Starts using an identity for every later call.</summary>
    public void Authenticate(X509Certificate2 certificate)
    {
        authenticated?.Dispose();
        authenticated = CreateClient(certificate);
    }

    public async Task<bool> HeartbeatAsync(Guid agentId, string version, string[] readers,
        IReadOnlyList<UnsupportedCardReport> unsupported, CancellationToken ct)
    {
        var response = await Authenticated().PostAsJsonAsync(
            $"/api/agents/{agentId}/heartbeat",
            new { version, readers, unsupported }, ct);

        return response.IsSuccessStatusCode;
    }

    public async Task<InventoryAccepted?> ReportInventoryAsync(TokenInventoryReport report,
        CancellationToken ct)
    {
        var response = await Authenticated()
            .PostAsJsonAsync("/api/tokens/inventory", report, ct);

        return response.IsSuccessStatusCode
            ? await response.Content.ReadFromJsonAsync<InventoryAccepted>(ct)
            : null;
    }

    private HttpClient Authenticated() => authenticated
        ?? throw new InvalidOperationException("The agent has no identity yet.");

    private HttpClient CreateClient(X509Certificate2? certificate)
    {
        var handler = new HttpClientHandler();

        if (certificate is not null)
        {
            handler.ClientCertificates.Add(certificate);
        }

        if (acceptAnyServerCertificate)
        {
            // Development certificates from scripts/dev-certs.sh are self-signed.
            handler.ServerCertificateCustomValidationCallback =
                HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        }

        return new HttpClient(handler) { BaseAddress = backend };
    }

    public void Dispose() => authenticated?.Dispose();

    private sealed record EnrolmentResponse(Guid AgentId, string CertificatePem);
}
