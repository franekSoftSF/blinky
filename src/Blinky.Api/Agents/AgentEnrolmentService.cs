using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Blinky.Api.Persistence;
using Blinky.Domain;
using Blinky.Domain.Entities;
using NHibernate.Linq;

namespace Blinky.Api.Agents;

/// <summary>
/// Turns a bootstrap token and a certificate request into an agent identity.
/// </summary>
public sealed class AgentEnrolmentService(
    Database database,
    AgentCertificateAuthority authority,
    string bootstrapToken,
    ILogger<AgentEnrolmentService> logger)
{
    public EnrolmentResult Enrol(EnrolmentRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Hostname) || string.IsNullOrWhiteSpace(request.Domain))
        {
            // The domain is required rather than derived: the agent runs as
            // LocalSystem, whose UserDomainName is the machine name, so
            // guessing here produces a second, orphaned row per machine.
            return new EnrolmentResult(EnrolmentOutcome.InvalidRequest,
                "hostname and domain are both required");
        }

        if (!IsBootstrapTokenValid(request.BootstrapToken))
        {
            logger.LogWarning("Enrolment refused for {Hostname}.{Domain}: bad bootstrap token",
                request.Hostname, request.Domain);

            return new EnrolmentResult(EnrolmentOutcome.InvalidToken, "bootstrap token rejected");
        }

        CertificateRequest signingRequest;
        try
        {
            // Loading verifies the signature on the request, which is what
            // makes it proof that the agent holds the private key.
            signingRequest = CertificateRequest.LoadSigningRequestPem(
                request.CertificateSigningRequest, HashAlgorithmName.SHA256);
        }
        catch (Exception ex)
        {
            return new EnrolmentResult(EnrolmentOutcome.InvalidRequest,
                $"the certificate request could not be read: {ex.Message}");
        }

        var hostname = request.Hostname.Trim().ToLowerInvariant();
        var domain = request.Domain.Trim().ToLowerInvariant();

        using var session = database.OpenSession();
        using var transaction = session.BeginTransaction();

        // Idempotent on (hostname, domain). Re-running the installer must
        // return the same agent rather than a second row that splits the
        // machine's history in two.
        var agent = session.Query<Agent>()
            .SingleOrDefault(a => a.Hostname == hostname && a.Domain == domain);

        var alreadyRegistered = agent is not null;
        var now = DateTime.UtcNow;

        if (agent is null)
        {
            agent = new Agent
            {
                Hostname = hostname,
                Domain = domain,
                State = AgentState.Enrolled,
                CreatedAt = now,
                UpdatedAt = now,
            };
        }

        X509Certificate2 issued;
        try
        {
            issued = authority.Issue(signingRequest, hostname, domain);
        }
        catch (Exception ex)
        {
            // An unhandled exception here becomes a 500 with no explanation on
            // the agent's side, which is a miserable thing to debug from a
            // workstation.
            logger.LogError(ex, "Issuing a certificate for {Hostname}.{Domain} failed",
                hostname, domain);

            return new EnrolmentResult(EnrolmentOutcome.Rejected,
                $"the agent certificate could not be issued: {ex.Message}");
        }

        using var _ = issued;

        agent.ClientCertificateThumbprint = issued.Thumbprint;
        agent.State = AgentState.Enrolled;
        agent.UpdatedAt = now;
        session.SaveOrUpdate(agent);

        session.Save(new AuditEvent
        {
            OccurredAt = now,
            EventType = alreadyRegistered ? "agent.re-enrolled" : "agent.enrolled",
            Actor = $"{hostname}.{domain}",
            SubjectType = nameof(Agent),
            SubjectId = agent.Id,
            Detail = $$"""{"thumbprint":"{{issued.Thumbprint}}"}""",
        });

        transaction.Commit();

        logger.LogInformation("Agent {Hostname}.{Domain} {Action} as {AgentId}",
            hostname, domain, alreadyRegistered ? "re-enrolled" : "enrolled", agent.Id);

        return new EnrolmentResult(EnrolmentOutcome.Issued, "issued",
            new EnrolmentResponse(agent.Id, issued.ExportCertificatePem(),
                authority.IssuerSubject, issued.NotAfter, alreadyRegistered));
    }

    /// <summary>
    /// Constant-time comparison. A token check that returns early leaks its
    /// prefix to anything that can time a request.
    /// </summary>
    private bool IsBootstrapTokenValid(string? presented)
    {
        if (string.IsNullOrEmpty(presented) || string.IsNullOrEmpty(bootstrapToken))
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.UTF8.GetBytes(presented),
            System.Text.Encoding.UTF8.GetBytes(bootstrapToken));
    }
}
