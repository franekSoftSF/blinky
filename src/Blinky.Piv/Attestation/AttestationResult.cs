namespace Blinky.Piv.Attestation;

/// <summary>Why an attestation was refused.</summary>
public enum AttestationFailure
{
    None,

    /// <summary>The chain does not reach a pinned Yubico root.</summary>
    UntrustedChain,

    /// <summary>The attestation names a different token than the one in the reader.</summary>
    SerialMismatch,

    /// <summary>The attestation is for a different slot than the one asked about.</summary>
    SlotMismatch,

    /// <summary>The attested key is not the key in the request.</summary>
    PublicKeyMismatch,

    /// <summary>The certificate is not a Yubico attestation at all.</summary>
    NotAnAttestation,

    /// <summary>The token's policies do not satisfy what the profile requires.</summary>
    PolicyNotSatisfied,
}

/// <summary>
/// The verdict, with the reason. Never a bare boolean: a rejected attestation
/// stops an issuance, and whoever reads that log line needs to know whether
/// they are holding the wrong token, the wrong slot, or a forgery.
/// </summary>
public sealed record AttestationResult(
    bool IsTrusted,
    AttestationFailure Failure,
    string Explanation,
    YubicoAttestation? Attestation)
{
    public static AttestationResult Trusted(YubicoAttestation attestation) =>
        new(true, AttestationFailure.None, "attestation verified", attestation);

    public static AttestationResult Rejected(AttestationFailure failure, string explanation,
        YubicoAttestation? attestation = null) =>
        new(false, failure, explanation, attestation);

    public override string ToString() =>
        IsTrusted ? "trusted" : $"rejected ({Failure}): {Explanation}";
}
