namespace Blinky.Piv;

/// <summary>What the card says about a key slot. Null where it cannot be asked.</summary>
public sealed record SlotMetadata(
    PivSlot Slot,
    PivAlgorithm Algorithm,
    PinPolicy PinPolicy,
    TouchPolicy TouchPolicy,
    KeyOrigin Origin,
    byte[]? PublicKey);

/// <summary>
/// What the card says about the management key. The algorithm is read, never
/// assumed: firmware before 5.7 ships 3DES and 5.7 or later ships AES-192, and
/// both are on this bench.
/// </summary>
public sealed record ManagementKeyMetadata(
    PivAlgorithm Algorithm,
    bool IsDefault,
    TouchPolicy TouchPolicy);

/// <summary>What the card says about the PIN or the PUK.</summary>
public sealed record PinMetadata(
    PinState State,
    int? TotalRetries,
    int? RemainingRetries)
{
    /// <summary>
    /// True when no PUK exists to unblock a PIN with. The only recovery left is
    /// a full PIV reset, which destroys every key on the token.
    /// </summary>
    public bool IsUnrecoverable => State is PinState.NotConfigured;
}

/// <summary>
/// On-card biometric comparison, slot 96. Present only on the Bio
/// Multi-protocol Edition; every other token answers the same command with
/// 6A88, and that is the detection.
/// </summary>
public sealed record BiometricMetadata(
    bool FingerprintsEnrolled,
    int? AttemptsRemaining,
    bool TemporaryPinSet)
{
    /// <summary>True when match attempts are exhausted and only the PIN is left.</summary>
    public bool IsBlocked => AttemptsRemaining == 0;
}

/// <summary>Everything one read-only pass over a token can establish.</summary>
public sealed record TokenInventory(
    uint? SerialNumber,
    FirmwareVersion Firmware,
    PinMetadata Pin,
    PinMetadata Puk,
    ManagementKeyMetadata? ManagementKey,
    BiometricMetadata? Biometrics,
    IReadOnlyList<SlotInventory> Slots)
{
    /// <summary>True when the token verifies its holder with a fingerprint.</summary>
    public bool IsBiometric => Biometrics is not null;
}

/// <summary>One slot: what key it holds, and what certificate, if any.</summary>
public sealed record SlotInventory(
    PivSlot Slot,
    bool HasCertificate,
    SlotMetadata? Metadata,
    byte[]? CertificateDer)
{
    /// <summary>
    /// True when the slot holds nothing at all. A slot with a key but no
    /// certificate is a different thing and is not empty.
    /// </summary>
    public bool IsEmpty => !HasCertificate && Metadata is null;
}
