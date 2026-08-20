namespace Blinky.Domain.Entities;

/// <summary>
/// One physical YubiKey. The serial is the identity, and the row outlives any
/// credential ever issued onto it.
/// </summary>
public class Token
{
    public virtual Guid Id { get; protected set; }

    public virtual long Serial { get; set; }

    public virtual string? FirmwareVersion { get; set; }

    public virtual string? FormFactor { get; set; }

    /// <summary>Thumbprint of the F9 certificate, pinned at registration.</summary>
    public virtual string? AttestationThumbprint { get; set; }

    public virtual TokenState State { get; set; } = TokenState.Detected;

    public virtual Cardholder? Cardholder { get; set; }

    public virtual string? ManagementKeyAlgorithm { get; set; }

    /// <summary>Which derivation generation is on the card. No key material here.</summary>
    public virtual int ManagementKeyVersion { get; set; }

    /// <summary>
    /// Its own field rather than something inferred: a token whose management
    /// key is neither the factory value nor the one Blinky would derive is
    /// unmanageable, and an operator has to see that in a list rather than
    /// discover it in a failed job.
    /// </summary>
    public virtual ManagementKeyState ManagementKeyState { get; set; } = ManagementKeyState.Unknown;

    public virtual CredentialSecretState PinState { get; set; } = CredentialSecretState.Unknown;

    public virtual CredentialSecretState PukState { get; set; } = CredentialSecretState.Unknown;

    public virtual BiometricState BiometricState { get; set; } = BiometricState.Unknown;

    public virtual short? PinRetriesLeft { get; set; }

    public virtual short? PukRetriesLeft { get; set; }

    public virtual short? BiometricAttemptsLeft { get; set; }

    public virtual DateTime? LastSeenAt { get; set; }

    public virtual Guid? LastSeenAgentId { get; set; }

    public virtual DateTime CreatedAt { get; set; }

    public virtual DateTime UpdatedAt { get; set; }

    /// <summary>
    /// True when a blocked PIN could only be resolved by wiping the token.
    /// Both reasons look the same to an operator; only one of them is a
    /// finding. See docs/02-data-model.md.
    /// </summary>
    public virtual bool IsUnrecoverable =>
        PukState is CredentialSecretState.Disabled or CredentialSecretState.NotApplicable;
}
