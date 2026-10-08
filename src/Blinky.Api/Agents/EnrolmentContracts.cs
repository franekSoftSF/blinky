namespace Blinky.Api.Agents;

/// <summary>What a machine sends to join the deployment.</summary>
/// <param name="Hostname">Short name. Part of the subject, which the server assigns.</param>
/// <param name="Domain">AD domain. Required rather than derived - see <c>Enrol</c>.</param>
/// <param name="BootstrapToken">
/// The enrolment token. Named for what the agent has always called it, so an
/// agent built before 0102 still speaks this protocol - what changed is that
/// the value is now a row with a term and a count rather than one string in
/// the compose file.
/// </param>
/// <param name="CertificateSigningRequest">PKCS#10. Only the public key is taken from it.</param>
/// <param name="Purpose">
/// "connector" when an ADCS connector is joining; anything else, including
/// absent, means a workstation agent. It selects the path, it does not grant
/// it: the token's own purpose has to match, so an agent token presented here
/// with "connector" is refused.
/// </param>
public sealed record EnrolmentRequest(
    string Hostname,
    string Domain,
    string BootstrapToken,
    string CertificateSigningRequest,
    string? Purpose = null);

/// <summary>What a connector gets back when it joins.</summary>
public sealed record ConnectorEnrolmentResponse(
    Guid ConnectorId,
    string CertificatePem,
    string IssuerSubject,
    DateTimeOffset NotAfter,
    string Fingerprint);

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

public sealed record ConnectorEnrolmentResult(
    EnrolmentOutcome Outcome,
    string Message,
    ConnectorEnrolmentResponse? Response = null);
