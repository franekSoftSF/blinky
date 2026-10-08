namespace Blinky.Contracts;

/// <summary>
/// The ADCS connector enrolling itself with a connector enrolment token (0105).
/// </summary>
/// <remarks>
/// The API side has taken this since 0102, in <c>Blinky.Api.Agents.EnrolmentRequest</c>,
/// and nothing on the connector sent it: a connector token could be made in the console
/// and spent by no one. These records are the same JSON, and a test keeps them so.
/// </remarks>
public static class ConnectorEnrolment
{
    /// <summary>The agents' enrolment route, shared because the token decides what enrols.</summary>
    public const string Path = "/api/agents/enroll";

    /// <summary>What <see cref="ConnectorEnrolmentRequest.Purpose"/> says for a connector.</summary>
    public const string Purpose = "connector";
}

/// <param name="Hostname">This machine's NetBIOS name.</param>
/// <param name="Domain">Its DNS domain, which a token restricted to one domain is checked against.</param>
/// <param name="BootstrapToken">The connector enrolment token, spent by this call.</param>
/// <param name="CertificateSigningRequest">PKCS#10 PEM; the key never leaves this machine.</param>
public sealed record ConnectorEnrolmentRequest(
    string Hostname,
    string Domain,
    string BootstrapToken,
    string CertificateSigningRequest,
    string Purpose = ConnectorEnrolment.Purpose);

public sealed record ConnectorEnrolmentAnswer(
    Guid ConnectorId,
    string CertificatePem,
    string IssuerSubject,
    DateTimeOffset NotAfter,
    string Fingerprint);
