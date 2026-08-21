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
    Blinky.Api.Jobs.JobService jobs,
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
    /// Withdraws a credential without touching the card it is on.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The ordinary way to withdraw one is a recycle job: the agent takes the
    /// certificate off the card and the record follows. That needs the card,
    /// an agent that can reach it, and a management key Blinky still holds.
    /// </para>
    /// <para>
    /// This is for when one of those is gone. A token reset outside Blinky, a
    /// card that left with somebody, a management key changed by another tool
    /// — the certificate is beyond reach and is still, as far as every relying
    /// party is concerned, valid. Refusing to revoke it because the card
    /// cannot be reached would leave the one credential that most needs
    /// revoking as the one that cannot be.
    /// </para>
    /// <para>
    /// The serial number goes on the revocation list, which is what actually
    /// withdraws it. The record is marked to match. What is physically on the
    /// card afterwards is unknown and is recorded as unknown rather than
    /// guessed at.
    /// </para>
    /// <para>
    /// Wanted on 21 August 2026, when a token's management key turned out to
    /// have been changed by another tool: two credentials, neither reachable,
    /// both still valid, and no way to say so.
    /// </para>
    /// </remarks>
    /// <returns>False when there is no such credential, or it was already revoked.</returns>
    public async Task<bool> RevokeAsync(Guid credentialId, Blinky.Pki.X509RevocationReason reason,
        string? comment, CancellationToken ct = default)
    {
        using var session = database.OpenSession();
        using var transaction = session.BeginTransaction();

        var credential = session.Get<Credential>(credentialId);
        if (credential is null || credential.State is DomainCredentialState.Revoked)
        {
            return false;
        }

        // A credential that never reached a certificate has no serial number
        // and so has nothing to put on a list. It is still worth closing the
        // record - a row stuck at Requested is a job somebody has to decide
        // about eventually - but saying it was revoked would claim a
        // revocation that no relying party will ever see.
        if (!string.IsNullOrEmpty(credential.SerialNumber))
        {
            // The list first. If publishing fails, nothing is marked: a record
            // that says revoked while the certificate is still good on every
            // revocation list is worse than one that says nothing yet.
            await authority.RevokeAsync(
                new RevocationRequest(credential.SerialNumber, reason, comment), ct);
        }

        var now = DateTime.UtcNow;

        credential.State = DomainCredentialState.Revoked;
        credential.RevokedAt = now;
        credential.RevocationReason = reason.ToString();
        credential.UpdatedAt = now;
        session.Update(credential);

        // The slot is no longer something Blinky put there and is not known to
        // be empty either: nobody has looked at the card. Stale is the honest
        // answer, and the next inventory sweep corrects it.
        var slot = session.Query<Slot>().SingleOrDefault(s =>
            s.Token.Id == credential.Token.Id && s.SlotId == credential.SlotId);

        if (slot is not null)
        {
            slot.State = Blinky.Domain.SlotState.Stale;
            slot.Credential = null;
            slot.UpdatedAt = now;
            session.Update(slot);
        }

        transaction.Commit();

        // Now rather than at the next scheduled publication. Somebody revokes
        // a credential because they want it to stop working, and a list that
        // still vouches for it for another two hours is the wrong answer to
        // "the card was lost this morning".
        //
        // Asked for rather than done: the worker builds the list, from one
        // place, and polls for these in seconds.
        jobs.RequestCrlPublication($"revoked:{credentialId}");

        return true;
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
