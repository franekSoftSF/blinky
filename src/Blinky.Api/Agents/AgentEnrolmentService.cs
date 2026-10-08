using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Blinky.Api.Persistence;
using Blinky.Domain;
using Blinky.Domain.Entities;
using NHibernate.Linq;

namespace Blinky.Api.Agents;

/// <summary>
/// Turns an enrolment token and a certificate request into an agent identity.
/// </summary>
/// <remarks>
/// The token used to be one string in <c>docker-compose.yml</c>, the same for
/// every machine and for the life of the deployment. It is a row now, with an
/// expiry, a count of uses and a withdrawal - see
/// <see cref="EnrolmentTokens"/> and patch 0102.
/// </remarks>
public sealed class AgentEnrolmentService(
    Database database,
    AgentCertificateAuthority authority,
    EnrolmentTokens tokens,
    ILogger<AgentEnrolmentService> logger)
{
    /// <summary>
    /// Issues a replacement for an agent that already has one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The subject comes from the registration, exactly as at enrolment: an
    /// agent renewing does not get to say who it is any more than an agent
    /// joining does.
    /// </para>
    /// <para>
    /// The recorded thumbprint moves as soon as the new certificate is issued,
    /// so the next request must use the new one. There is no overlap here and
    /// none is needed: the agent installs it before its next call, and if that
    /// fails it still holds a certificate valid for another month.
    /// </para>
    /// </remarks>
    public EnrolmentResult Renew(Guid agentId, RenewalRequest request)
    {
        CertificateRequest signingRequest;

        try
        {
            signingRequest = CertificateRequest.LoadSigningRequestPem(
                request.CertificateSigningRequest, HashAlgorithmName.SHA256);
        }
        catch (Exception ex)
        {
            return new EnrolmentResult(EnrolmentOutcome.InvalidRequest,
                $"the certificate request could not be read: {ex.Message}");
        }

        using var session = database.OpenSession();
        using var transaction = session.BeginTransaction();

        var agent = session.Get<Agent>(agentId);

        if (agent is null || agent.State is not AgentState.Enrolled)
        {
            return new EnrolmentResult(EnrolmentOutcome.Rejected, "this agent is not enrolled");
        }

        X509Certificate2 issued;

        try
        {
            issued = authority.Issue(signingRequest, agent.Hostname, agent.Domain);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Renewing the certificate for {Hostname}.{Domain} failed",
                agent.Hostname, agent.Domain);

            return new EnrolmentResult(EnrolmentOutcome.Rejected,
                $"the agent certificate could not be issued: {ex.Message}");
        }

        using var _ = issued;

        var previous = agent.ClientCertificateThumbprint;
        var now = DateTime.UtcNow;

        agent.ClientCertificateThumbprint = issued.Thumbprint;
        agent.UpdatedAt = now;
        session.Update(agent);

        session.Save(new AuditEvent
        {
            OccurredAt = now,
            EventType = "agent.certificate-renewed",
            Actor = $"{agent.Hostname}.{agent.Domain}",
            SubjectType = nameof(Agent),
            SubjectId = agent.Id,
            Detail = $$"""{"from":"{{previous}}","to":"{{issued.Thumbprint}}"}""",
        });

        transaction.Commit();

        logger.LogInformation("Renewed the certificate for {Hostname}.{Domain}, valid until "
                              + "{NotAfter:yyyy-MM-dd}", agent.Hostname, agent.Domain,
            issued.NotAfter);

        return new EnrolmentResult(EnrolmentOutcome.Issued, "renewed",
            new EnrolmentResponse(agent.Id, issued.ExportCertificatePem(),
                authority.IssuerSubject, issued.NotAfter, AlreadyRegistered: true));
    }

    /// <summary>
    /// The same ceremony for an ADCS connector, which is one machine and not a
    /// fleet.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The certificate comes from the same CA as an agent's, because that is
    /// the anchor the edge verifies on the agent listener. What differs is what
    /// the server writes down: a connector gets a registration row rather than
    /// an agent row, so it is a connector on the connector routes and a
    /// stranger on every agent route.
    /// </para>
    /// <para>
    /// Before 0102 this was a person running tools/AgentEnrol with the shared
    /// bootstrap token and then pasting the certificate's fingerprint into
    /// .env. Two manual steps, one of them a secret with no expiry, and
    /// nothing in the console could see the result.
    /// </para>
    /// </remarks>
    public ConnectorEnrolmentResult EnrolConnector(EnrolmentRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Hostname) || string.IsNullOrWhiteSpace(request.Domain))
        {
            return new ConnectorEnrolmentResult(EnrolmentOutcome.InvalidRequest,
                "hostname and domain are both required");
        }

        var (outcome, token) = tokens.Spend(
            request.BootstrapToken, EnrolmentPurpose.AdcsConnector, request.Domain);

        if (outcome != TokenOutcome.Accepted)
        {
            logger.LogWarning("Connector enrolment refused for {Hostname}.{Domain}: token rejected",
                request.Hostname, request.Domain);

            return new ConnectorEnrolmentResult(EnrolmentOutcome.InvalidToken, "enrolment token rejected");
        }

        CertificateRequest signingRequest;

        try
        {
            signingRequest = CertificateRequest.LoadSigningRequestPem(
                request.CertificateSigningRequest, HashAlgorithmName.SHA256);
        }
        catch (Exception ex)
        {
            return new ConnectorEnrolmentResult(EnrolmentOutcome.InvalidRequest,
                $"the certificate request could not be read: {ex.Message}");
        }

        using var issued = authority.Issue(signingRequest, request.Hostname, request.Domain);
        var fingerprint = issued.GetCertHashString(System.Security.Cryptography.HashAlgorithmName.SHA256);
        var now = DateTime.UtcNow;

        using var session = database.OpenSession();
        using var transaction = session.BeginTransaction();

        // One row per certificate. A connector that re-enrols gets a second
        // row and the old fingerprint keeps working until somebody withdraws
        // it, which is what lets a connector be replaced without an outage.
        var registration = new ConnectorRegistration
        {
            Name = $"{request.Hostname}.{request.Domain}",
            Fingerprint = fingerprint,
            EnrolmentTokenId = token!.Id,
            EnrolledAt = now,
            CertificateNotAfter = issued.NotAfter,
        };

        session.Save(registration);

        session.Save(new AuditEvent
        {
            OccurredAt = now,
            EventType = "connector.enrolled",
            Actor = registration.Name,
            SubjectType = nameof(ConnectorRegistration),
            SubjectId = registration.Id,
            Detail = $$"""{"fingerprint":"{{fingerprint}}","token":"{{token.Name}}"}""",
        });

        transaction.Commit();

        logger.LogInformation("ADCS connector {Name} enrolled with token {Token}; fingerprint {Fingerprint}",
            registration.Name, token.Name, fingerprint);

        return new ConnectorEnrolmentResult(EnrolmentOutcome.Issued, "enrolled",
            new ConnectorEnrolmentResponse(registration.Id, issued.ExportCertificatePem(),
                authority.IssuerSubject, issued.NotAfter, fingerprint));
    }

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

        // Spent here, before the certificate exists. A token's limits are
        // counted in their own transaction so that two machines presenting the
        // last use of one token cannot both win (0102).
        var (outcome, token) = tokens.Spend(
            request.BootstrapToken, EnrolmentPurpose.Agent, request.Domain);

        if (outcome != TokenOutcome.Accepted)
        {
            logger.LogWarning("Enrolment refused for {Hostname}.{Domain}: enrolment token rejected",
                request.Hostname, request.Domain);

            return new EnrolmentResult(EnrolmentOutcome.InvalidToken, "enrolment token rejected");
        }

        logger.LogInformation("Enrolment token {Name} spent by {Hostname}.{Domain}: use {Use} of {Uses}",
            token!.Name, request.Hostname, request.Domain, token.Uses,
            token.MaxUses?.ToString() ?? "unlimited");

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

}
