using System.Security.Cryptography.X509Certificates;

namespace Blinky.Piv.Attestation;

/// <summary>
/// Decides whether a key really was generated on a genuine token, before any CA
/// is asked to sign anything.
/// </summary>
/// <remarks>
/// <para>
/// The chain is leaf, then the token's own F9 certificate, then a pinned Yubico
/// root. Only the root is pinned, and that is not a simplification: the
/// intermediate is <b>different on every device</b> - three tokens on the bench
/// produced three intermediates with the same names and three different serial
/// numbers. Pinning an intermediate would produce code that works on the token
/// it was written against and fails on every other one.
/// </para>
/// <para>
/// It follows that the intermediate is untrusted input read from the card, and
/// is verified rather than assumed.
/// </para>
/// </remarks>
public sealed class AttestationVerifier(X509Certificate2Collection trustedRoots)
{
    private readonly X509Certificate2Collection roots = trustedRoots.Count > 0
        ? trustedRoots
        : throw new ArgumentException(
            "At least one trusted root is required; verifying against none would accept anything.",
            nameof(trustedRoots));

    /// <summary>
    /// Verifies an attestation. <paramref name="expectedSerial"/> is the serial
    /// read from the token over PC/SC, and <paramref name="expectedPublicKey"/>
    /// is the SubjectPublicKeyInfo of the key in the certificate request.
    /// </summary>
    public AttestationResult Verify(
        X509Certificate2 leaf,
        X509Certificate2 intermediate,
        PivSlot expectedSlot,
        uint? expectedSerial = null,
        byte[]? expectedPublicKey = null)
    {
        var attestation = YubicoAttestation.Parse(leaf);

        if (attestation.SerialNumber is null && attestation.Firmware == FirmwareVersion.Unknown)
        {
            return AttestationResult.Rejected(AttestationFailure.NotAnAttestation,
                "the certificate carries no Yubico attestation extensions");
        }

        // The chain first: everything below is a statement made by the
        // certificate, and none of it means anything until the certificate is
        // known to come from Yubico.
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.AddRange(roots);
        chain.ChainPolicy.ExtraStore.Add(intermediate);

        // Attestation certificates have no CRL or OCSP, and the agent may be
        // offline. Revocation checking here would fail for the wrong reason.
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

        if (!chain.Build(leaf))
        {
            var reasons = string.Join(", ", chain.ChainStatus
                .Select(s => s.StatusInformation.Trim())
                .Where(s => s.Length > 0)
                .DefaultIfEmpty("no chain to a pinned Yubico root"));

            return AttestationResult.Rejected(AttestationFailure.UntrustedChain, reasons,
                attestation);
        }

        if (attestation.Slot is null || attestation.Slot.Value.Id != expectedSlot.Id)
        {
            return AttestationResult.Rejected(AttestationFailure.SlotMismatch,
                $"attestation is for slot {attestation.Slot?.Name ?? "?"}, expected {expectedSlot}",
                attestation);
        }

        if (expectedSerial is not null && attestation.SerialNumber != expectedSerial)
        {
            return AttestationResult.Rejected(AttestationFailure.SerialMismatch,
                $"attestation names token {attestation.SerialNumber?.ToString() ?? "?"}, "
                + $"the reader holds {expectedSerial}",
                attestation);
        }

        if (expectedPublicKey is not null
            && !attestation.PublicKeyInfo.AsSpan().SequenceEqual(expectedPublicKey))
        {
            return AttestationResult.Rejected(AttestationFailure.PublicKeyMismatch,
                "the attested key is not the key in the request", attestation);
        }

        return AttestationResult.Trusted(attestation);
    }

    /// <summary>
    /// Checks the token's own policies against what a profile demands. Separate
    /// from <see cref="Verify"/> because it is a policy decision, not a
    /// question about authenticity.
    /// </summary>
    public static AttestationResult RequirePolicies(
        AttestationResult verified, PinPolicy? requiredPin, TouchPolicy? requiredTouch)
    {
        if (!verified.IsTrusted || verified.Attestation is null)
        {
            return verified;
        }

        var attestation = verified.Attestation;

        if (requiredPin is not null && attestation.PinPolicy != requiredPin)
        {
            return AttestationResult.Rejected(AttestationFailure.PolicyNotSatisfied,
                $"key was generated with PIN policy {attestation.PinPolicy}, "
                + $"the profile requires {requiredPin}", attestation);
        }

        if (requiredTouch is not null && attestation.TouchPolicy != requiredTouch)
        {
            return AttestationResult.Rejected(AttestationFailure.PolicyNotSatisfied,
                $"key was generated with touch policy {attestation.TouchPolicy}, "
                + $"the profile requires {requiredTouch}", attestation);
        }

        return verified;
    }
}
