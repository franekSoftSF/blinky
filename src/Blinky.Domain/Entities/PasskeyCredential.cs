namespace Blinky.Domain.Entities;

/// <summary>
/// One WebAuthn credential Blinky created on a key and registered with a
/// provider on somebody's behalf.
/// </summary>
/// <remarks>
/// <para>
/// History, not configuration: created and moved through its states, never
/// edited and never deleted. Revoking deletes the credential at the provider and
/// keeps this row, which is the point of having it.
/// </para>
/// <para>
/// There is no PIN here and no column to put one in. The provisional PIN is
/// shown on the workstation and nowhere else; what is recorded is only whether
/// the agent set one.
/// </para>
/// </remarks>
public class PasskeyCredential
{
    public virtual Guid Id { get; protected set; }

    /// <summary>The configured provider instance, by name - "entra", "okta-eu".</summary>
    public virtual string Directory { get; set; } = string.Empty;

    /// <summary>The provider's id for the user. Stable where the login is not.</summary>
    public virtual string ProviderUserId { get; set; } = string.Empty;

    /// <summary>UPN or Okta login when it was registered. A snapshot; a rename does not rewrite it.</summary>
    public virtual string ProviderLogin { get; set; } = string.Empty;

    public virtual Cardholder? Cardholder { get; set; }

    /// <summary>Null for a key that did not report one.</summary>
    public virtual long? TokenSerial { get; set; }

    public virtual Guid? JobId { get; set; }

    /// <summary>
    /// Derived from the job and the challenge (<c>Fido2CeremonyRequest.IdFor</c>).
    /// The same challenge answered twice is recognised here as one ceremony.
    /// </summary>
    public virtual Guid? CeremonyId { get; set; }

    /// <summary>
    /// What was handed to the key, unpadded base64url. Not a secret - it is a
    /// nonce - and kept so that the clientDataJSON coming back can be checked
    /// against what was sent rather than against what the agent says was sent.
    /// </summary>
    public virtual string? Challenge { get; set; }

    public virtual DateTime? ChallengeDeadlineAt { get; set; }

    /// <summary>What the provider needs to clean up an unfinished ceremony: Okta's pending factor id.</summary>
    public virtual string? ProviderReference { get; set; }

    /// <summary>Unpadded base64url, as the key produced it.</summary>
    public virtual string? CredentialId { get; set; }

    public virtual Guid? Aaguid { get; set; }

    /// <summary>The name it was registered under, serial included when asked for.</summary>
    public virtual string? KeyName { get; set; }

    /// <summary>Kept for the audit trail: what the provider was shown, byte for byte.</summary>
    public virtual byte[]? AttestationObject { get; set; }

    /// <summary>The provider's id for the method - Entra's fido2Method id, Okta's factor id.</summary>
    public virtual string? ProviderMethodId { get; set; }

    /// <summary>Whether the agent set the FIDO2 PIN. Never what it was.</summary>
    public virtual bool PinSetByAgent { get; set; }

    public virtual PasskeyCredentialState State { get; protected set; } = PasskeyCredentialState.Requested;

    public virtual string? FailureReason { get; protected set; }

    public virtual DateTime? RegisteredAt { get; protected set; }

    public virtual string? RevocationReason { get; protected set; }

    public virtual DateTime? RevokedAt { get; protected set; }

    public virtual DateTime CreatedAt { get; set; }

    public virtual DateTime UpdatedAt { get; set; }

    /// <summary>
    /// The only way the state changes. A move the lifecycle does not allow is a
    /// bug in whoever asked, and is refused here rather than recorded.
    /// </summary>
    /// <param name="reason">Required for <see cref="PasskeyCredentialState.Failed"/> and <see cref="PasskeyCredentialState.Revoked"/>.</param>
    public virtual void MoveTo(PasskeyCredentialState next, DateTime nowUtc, string? reason = null)
    {
        if (!PasskeyCredentialStates.CanMove(State, next))
        {
            throw new InvalidOperationException(
                $"A passkey cannot go from {State} to {next}; from {State} it may go to "
                + $"{(PasskeyCredentialStates.From(State) is { Count: > 0 } allowed ? string.Join(", ", allowed) : "nothing")}.");
        }

        if (next is PasskeyCredentialState.Failed or PasskeyCredentialState.Revoked
            && string.IsNullOrWhiteSpace(reason))
        {
            throw new ArgumentException($"Moving a passkey to {next} needs a reason.", nameof(reason));
        }

        switch (next)
        {
            case PasskeyCredentialState.Failed:
                FailureReason = reason;
                break;
            case PasskeyCredentialState.Registered:
                RegisteredAt = nowUtc;
                break;
            case PasskeyCredentialState.Revoked:
                RevocationReason = reason;
                RevokedAt = nowUtc;
                break;
        }

        State = next;
        UpdatedAt = nowUtc;
    }
}
