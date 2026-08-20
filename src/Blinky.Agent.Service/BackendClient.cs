using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Blinky.Contracts;

namespace Blinky.Agent.Service;

/// <summary>Everything the agent says to the backend.</summary>
public sealed class BackendClient : IDisposable
{
    private readonly Uri backend;
    private readonly X509Certificate2Collection pinnedRoots = [];
    private readonly bool acceptAnyServerCertificate;

    private HttpClient? authenticated;

    /// <summary>
    /// <paramref name="serverCertificateAuthorityPath"/> is the CA that signed
    /// the edge certificate. Pinning it is how an agent on one machine can
    /// believe a backend on another; the alternative,
    /// <paramref name="acceptAnyServerCertificate"/>, checks nothing and is for
    /// a single-machine bench.
    /// </summary>
    public BackendClient(Uri backend, string? serverCertificateAuthorityPath = null,
        bool acceptAnyServerCertificate = false)
    {
        this.backend = backend;
        this.acceptAnyServerCertificate = acceptAnyServerCertificate;

        if (!string.IsNullOrWhiteSpace(serverCertificateAuthorityPath))
        {
            // CreateFromPem, not CreateFromPemFile: the File overload wants a
            // private key in the same file and fails with "the key does not
            // match the certificate" when handed a plain CA certificate, which
            // is the only thing anyone would ever pin. Nothing here needs a
            // key - this certificate is a trust anchor, not an identity.
            pinnedRoots.Add(X509Certificate2.CreateFromPem(
                File.ReadAllText(serverCertificateAuthorityPath)));
        }
    }

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

    /// <summary>
    /// Asks for work. Null means there is none, which is the normal answer.
    /// </summary>
    public async Task<JobClaim?> ClaimJobAsync(CancellationToken ct)
    {
        var response = await Authenticated().GetAsync("/api/jobs/next", ct);

        if (response.StatusCode == System.Net.HttpStatusCode.NoContent
            || !response.IsSuccessStatusCode)
        {
            return null;
        }

        return await response.Content.ReadFromJsonAsync<JobClaim>(ct);
    }

    /// <summary>
    /// Reports a state change. Throws when the server will not take it: a
    /// report the server rejects means the agent's idea of the job and the
    /// server's have diverged, and carrying on would produce work nobody
    /// recorded.
    /// </summary>
    public async Task ReportProgressAsync(JobProgress progress, CancellationToken ct)
    {
        var response = await Authenticated().PostAsJsonAsync(
            $"/api/jobs/{progress.JobId}/progress", progress, ct);

        await ThrowIfRefused(response, "progress", progress.JobId, ct);
    }

    public async Task CompleteJobAsync(JobResult result, CancellationToken ct)
    {
        var response = await Authenticated().PostAsJsonAsync(
            $"/api/jobs/{result.JobId}/result", result, ct);

        await ThrowIfRefused(response, "result", result.JobId, ct);
    }

    private static async Task ThrowIfRefused(HttpResponseMessage response, string what,
        Guid jobId, CancellationToken ct)
    {
        if (response.IsSuccessStatusCode)
        {
            return;
        }

        throw new InvalidOperationException(
            $"The backend refused the {what} for job {jobId}: {(int)response.StatusCode} "
            + await response.Content.ReadAsStringAsync(ct));
    }

    public async Task<IssuedCredential> IssueCredentialAsync(IssueCredentialRequest request,
        CancellationToken ct)
    {
        var response = await Authenticated().PostAsJsonAsync("/api/credentials/issue", request, ct);

        if (!response.IsSuccessStatusCode)
        {
            // 422 is a refusal with a reason in it, and the reason is the whole
            // point - it says which rule the request broke.
            throw new InvalidOperationException(
                $"Issuance refused: {(int)response.StatusCode} "
                + await response.Content.ReadAsStringAsync(ct));
        }

        return await response.Content.ReadFromJsonAsync<IssuedCredential>(ct)
               ?? throw new InvalidOperationException("Issuance returned no certificate.");
    }

    public async Task ConfirmInstalledAsync(CredentialInstalled confirmation, CancellationToken ct)
    {
        var response = await Authenticated().PostAsJsonAsync(
            $"/api/credentials/{confirmation.CredentialId}/installed", confirmation, ct);

        await ThrowIfRefused(response, "installation", confirmation.CredentialId, ct);
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

    /// <summary>
    /// What the backend holds for a token, so the agent can compare it with
    /// what is actually on the card.
    /// </summary>
    /// <returns>
    /// Null when the backend could not be asked — which is not the same as an
    /// empty list, and the caller must not treat it as one. A backend that is
    /// unreachable makes every slot <b>unknown</b>, never <b>unmanaged</b>.
    /// </returns>
    public async Task<IReadOnlyList<KnownCredential>?> GetKnownCredentialsAsync(long serial,
        CancellationToken ct)
    {
        try
        {
            var response = await Authenticated()
                .GetAsync($"/api/tokens/{serial}/credentials", ct);

            return response.IsSuccessStatusCode
                ? await response.Content.ReadFromJsonAsync<List<KnownCredential>>(ct)
                : null;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException
                                      or InvalidOperationException)
        {
            return null;
        }
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

        if (pinnedRoots.Count > 0)
        {
            handler.ServerCertificateCustomValidationCallback = ValidateAgainstPinnedRoot;
        }
        else if (acceptAnyServerCertificate)
        {
            handler.ServerCertificateCustomValidationCallback =
                HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        }

        return new HttpClient(handler) { BaseAddress = backend };
    }

    /// <summary>
    /// Accepts a server certificate that chains to the pinned CA.
    /// </summary>
    /// <remarks>
    /// The name check has to be repeated by hand. Installing a custom callback
    /// replaces the platform's validation entirely, so a callback that only
    /// checks the chain would accept <b>any</b> host holding a certificate from
    /// that CA - which, in a lab where the CA also signs the test agent's
    /// issuer, is not a small hole.
    /// </remarks>
    private bool ValidateAgainstPinnedRoot(HttpRequestMessage request,
        X509Certificate2? certificate, X509Chain? chain, SslPolicyErrors errors)
    {
        if (certificate is null)
        {
            return false;
        }

        if (errors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch))
        {
            return false;
        }

        using var pinned = new X509Chain();
        pinned.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        pinned.ChainPolicy.CustomTrustStore.AddRange(pinnedRoots);
        pinned.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

        return pinned.Build(certificate);
    }

    public void Dispose() => authenticated?.Dispose();

    private sealed record EnrolmentResponse(Guid AgentId, string CertificatePem);
}

/// <summary>One credential the backend holds for a token.</summary>
/// <remarks>
/// The join is <see cref="PublicKeySha256"/>, not the certificate: a
/// certificate can be replaced in a slot while the key stays, and the key is
/// what the card proved it holds.
/// </remarks>
public sealed record KnownCredential(
    string SlotId,
    string? SerialNumber,
    string? PublicKeySha256,
    string State,
    string? SubjectDn,
    DateTimeOffset? NotAfter);
