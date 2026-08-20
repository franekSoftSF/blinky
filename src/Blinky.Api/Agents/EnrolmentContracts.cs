namespace Blinky.Api.Agents;

/// <summary>What an agent sends to join the fleet.</summary>
public sealed record EnrolmentRequest(
    string Hostname,
    string Domain,
    string BootstrapToken,
    string CertificateSigningRequest);

/// <summary>What it gets back.</summary>
public sealed record EnrolmentResponse(
    Guid AgentId,
    string CertificatePem,
    string IssuerSubject,
    DateTimeOffset NotAfter,
    bool AlreadyRegistered);

/// <summary>
/// An agent asking for a fresh certificate before its current one expires.
/// </summary>
/// <remarks>
/// No bootstrap token: the agent proves itself with the certificate it already
/// holds, over mTLS. That is the point — a token good for joining the fleet
/// should be needed once per machine, not every ninety days.
/// </remarks>
public sealed record RenewalRequest(string CertificateSigningRequest);

public enum EnrolmentOutcome
{
    Issued,
    InvalidToken,
    InvalidRequest,
    Rejected,
}

public sealed record EnrolmentResult(
    EnrolmentOutcome Outcome,
    string Message,
    EnrolmentResponse? Response = null);
