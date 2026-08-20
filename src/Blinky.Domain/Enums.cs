namespace Blinky.Domain;

/// <summary>Whether a PIN or PUK is at its factory value, set, or gone.</summary>
public enum CredentialSecretState
{
    /// <summary>Firmware too old to be asked. Not the same as "not set".</summary>
    Unknown,
    Default,
    Set,
    Blocked,

    /// <summary>Deleted or blocked on a token that is otherwise fine.</summary>
    Disabled,

    /// <summary>
    /// No PUK by design. A Bio Multi-protocol ships this way, and refusing it
    /// as broken would refuse the product line.
    /// </summary>
    NotApplicable,
}

/// <summary>What is known about the management key on a token.</summary>
public enum ManagementKeyState
{
    Unknown,
    Default,
    Diversified,

    /// <summary>Neither the factory key nor ours. The token is unmanageable.</summary>
    Lost,
}

/// <summary>On-card biometric comparison.</summary>
public enum BiometricState
{
    Unknown,
    NotSupported,
    NotEnrolled,
    Enrolled,
    Blocked,
}

/// <summary>What a slot holds.</summary>
public enum SlotState
{
    Empty,
    KeyPresent,
    Provisioned,

    /// <summary>
    /// Holds something Blinky did not put there. First-class, because it is
    /// what every token touched by ykman looks like, and overwriting silently
    /// is the wrong default.
    /// </summary>
    Stale,
}

/// <summary>Where a cardholder's identity comes from.</summary>
public enum DirectorySource
{
    Local,
    ActiveDirectory,
    Samba4,
}

public enum CardholderState
{
    Active,
    Suspended,
    Offboarded,
}

public enum AgentState
{
    Enrolled,
    Suspended,
    Incompatible,
    Retired,
}

/// <summary>Which CA a profile issues from.</summary>
public enum CaBackend
{
    BuiltIn,
    Adcs,
}

/// <summary>See docs/04-pki-backends.md - immutable once an instance exists.</summary>
public enum CaTopology
{
    Single,
    TwoTier,
}

/// <summary>What a <see cref="Entities.SecretEnvelope"/> protects.</summary>
public enum SecretKind
{
    Puk,
    ManagementKey,

    /// <summary>
    /// A PUK handed out but not yet confirmed on the card.
    /// </summary>
    /// <remarks>
    /// Kept apart from <see cref="Puk"/> so that an unblock which died between
    /// the reset and the rotation does not lose the value the card is still
    /// holding. Both exist until an agent says the card took the new one.
    /// </remarks>
    PukPending,
}
