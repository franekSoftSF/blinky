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
