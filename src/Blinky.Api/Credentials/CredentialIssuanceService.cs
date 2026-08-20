using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Blinky.Api.Persistence;
using Blinky.Contracts;
using Blinky.Domain.Entities;
using Blinky.Piv;
using Blinky.Piv.Attestation;
using Blinky.Pki;
using NHibernate.Linq;
using DomainCredentialState = Blinky.Domain.CredentialState;

namespace Blinky.Api.Credentials;

/// <summary>
/// Turns a request from a workstation into a certificate, or refuses it.
/// </summary>
/// <remarks>
/// Everything that decides whether a credential should exist happens here. The
/// agent generated the key and assembled the request; it does not get to say
/// whether the result is trustworthy.
/// </remarks>
public sealed class CredentialIssuanceService(
    Database database,
    ICertificateAuthority authority,
    ILogger<CredentialIssuanceService> logger)
{
    private readonly AttestationVerifier verifier = new(YubicoRoots.PivAttestation);

    public async Task<IssuedCredential> IssueAsync(IssueCredentialRequest request,
        CancellationToken ct)
    {
        var slot = PivSlot.Credentials.FirstOrDefault(s =>
            s.Name.Equals(request.SlotId, StringComparison.OrdinalIgnoreCase));

        if (slot.Id == 0)
        {
            throw new IssuancePolicyException($"{request.SlotId} is not a credential slot.");
        }

        using var leaf = X509Certificate2.CreateFromPem(request.AttestationPem);
        using var intermediate = X509Certificate2.CreateFromPem(request.AttestationIntermediatePem);

        // Verified here, against this server's pinned root. The agent checked
        // it too, and that check is worth exactly nothing to anyone but the
        // agent.
        var attestation = verifier.Verify(leaf, intermediate, slot,
            (uint)request.TokenSerial);

        if (!attestation.IsTrusted)
        {
            logger.LogWarning("Refused a credential for token {Serial}: {Result}",
                request.TokenSerial, attestation);

            throw new IssuancePolicyException(
                $"The attestation was not accepted: {attestation.Explanation}");
        }

        var attested = attestation.Attestation!;

        var context = new CertificateRequestContext(
            DecodePem(request.CertificateSigningRequestPem, "CERTIFICATE REQUEST"),
            new AttestedKey(request.TokenSerial, slot.Name, attested.PublicKeyInfo,
                attested.PinPolicy.ToString(), attested.TouchPolicy.ToString()),
            new CardholderIdentity(request.Cardholder.DisplayName, request.Cardholder.Upn,
                request.Cardholder.ObjectSid, null),
            Profiles.ByName(request.ProfileName, slot.Name));

        var issued = await authority.IssueAsync(context, ct);

        var credentialId = Record(request, issued, slot.Name);

        logger.LogInformation("Issued {Serial} for token {Token} slot {Slot} to {Subject}",
            issued.SerialNumber, request.TokenSerial, slot, issued.Certificate.Subject);

        return new IssuedCredential(credentialId, slot.Name, issued.CertificatePem,
            issued.Certificate.Issuer, issued.SerialNumber, issued.Certificate.NotAfter);
    }

    /// <summary>
    /// Marks a credential as actually on the card.
    /// </summary>
    /// <returns>False when there is no such credential to confirm.</returns>
    public bool MarkInstalled(CredentialInstalled confirmation)
    {
        using var session = database.OpenSession();
        using var transaction = session.BeginTransaction();

        var credential = session.Get<Credential>(confirmation.CredentialId);
        if (credential is null)
        {
            return false;
        }

        var now = DateTime.UtcNow;

        credential.State = DomainCredentialState.Installed;
        credential.UpdatedAt = now;
        session.Update(credential);

        // The slot now holds something Blinky put there, which is what makes it
        // Provisioned rather than Stale on the next inventory pass.
        var slot = session.Query<Slot>().SingleOrDefault(s =>
            s.Token.Id == credential.Token.Id && s.SlotId == credential.SlotId);

        if (slot is not null)
        {
            slot.State = Blinky.Domain.SlotState.Provisioned;
            slot.Credential = credential;
            slot.UpdatedAt = now;
            session.Update(slot);
        }

        session.Save(new AuditEvent
        {
            OccurredAt = now,
            EventType = "credential.installed",
            SubjectType = nameof(Credential),
            SubjectId = credential.Id,
            TokenSerial = credential.Token.Serial,
            Detail = $$"""{"thumbprint":"{{confirmation.Thumbprint}}"}""",
        });

        transaction.Commit();

        return true;
    }

    private Guid Record(IssueCredentialRequest request, IssuedCertificate issued, string slotId)
    {
        using var session = database.OpenSession();
        using var transaction = session.BeginTransaction();

        var token = session.Query<Token>().SingleOrDefault(t => t.Serial == request.TokenSerial)
                    ?? throw new IssuancePolicyException(
                        $"Token {request.TokenSerial} has never been seen by an agent.");

        var now = DateTime.UtcNow;

        var credential = new Credential
        {
            Token = token,
            SlotId = slotId,
            SerialNumber = issued.SerialNumber,
            IssuerDn = issued.Certificate.Issuer,
            SubjectDn = issued.Certificate.Subject,
            NotBefore = issued.Certificate.NotBefore.ToUniversalTime(),
            NotAfter = issued.Certificate.NotAfter.ToUniversalTime(),
            PublicKeySha256 = SHA256.HashData(
                issued.Certificate.PublicKey.ExportSubjectPublicKeyInfo()),

            // Issued, not Installed. The card does not have it yet, and saying
            // otherwise here would hide every certificate that never arrives.
            State = DomainCredentialState.Issued,
            CreatedAt = now,
            UpdatedAt = now,
        };

        session.Save(credential);

        session.Save(new AuditEvent
        {
            OccurredAt = now,
            EventType = "credential.issued",
            SubjectType = nameof(Credential),
            SubjectId = credential.Id,
            TokenSerial = token.Serial,
            Detail = $$"""{"serial":"{{issued.SerialNumber}}","slot":"{{slotId}}"}""",
        });

        transaction.Commit();

        return credential.Id;
    }

    private static byte[] DecodePem(string pem, string label)
    {
        var body = pem
            .Replace($"-----BEGIN {label}-----", string.Empty, StringComparison.Ordinal)
            .Replace($"-----END {label}-----", string.Empty, StringComparison.Ordinal);

        return Convert.FromBase64String(body.Replace("\r", string.Empty, StringComparison.Ordinal)
            .Replace("\n", string.Empty, StringComparison.Ordinal));
    }
}

/// <summary>
/// The profiles this build knows.
/// </summary>
/// <remarks>
/// In code rather than in the database, which is the open half of patch 0022.
/// Named here so that gap is visible from the thing that depends on it.
/// </remarks>
public static class Profiles
{
    public const string SmartCardLogon = "smartcard-logon";

    /// <summary>
    /// Client authentication and nothing else.
    /// </summary>
    /// <remarks>
    /// This exists because <see cref="SmartCardLogon"/> refuses to issue
    /// without a resolved <c>objectSid</c>, and that refusal is right: since
    /// KB5014754 a domain controller ignores a certificate mapped by name
    /// alone, so a logon certificate without the SID extension is one that
    /// will be rejected at the only moment it matters. The tempting fix — put
    /// a plausible SID in and move on — produces a certificate that asserts an
    /// identity nobody issued.
    /// <para>
    /// So: a profile that does not claim to be a logon credential. Useful
    /// before a directory exists, and deliberately missing both the Smart Card
    /// Logon EKU and the UPN SAN so it cannot be mistaken for one.
    /// </para>
    /// </remarks>
    public const string ClientAuthentication = "client-auth";

    public static IssuanceProfile ByName(string name, string slotId) => name switch
    {
        SmartCardLogon => new IssuanceProfile(SmartCardLogon, slotId, "ECCP256", 365,
            ["1.3.6.1.5.5.7.3.2", Pki.BuiltIn.BuiltInCertificateAuthority.SmartCardLogonOid],
            IncludeUpnSan: true, IncludeSidExtension: true),

        ClientAuthentication => new IssuanceProfile(ClientAuthentication, slotId, "ECCP256", 365,
            ["1.3.6.1.5.5.7.3.2"],
            IncludeUpnSan: false, IncludeSidExtension: false),

        _ => throw new IssuancePolicyException($"There is no profile called {name}."),
    };
}
