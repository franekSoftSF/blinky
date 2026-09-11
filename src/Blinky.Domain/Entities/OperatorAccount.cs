namespace Blinky.Domain.Entities;

/// <summary>
/// Somebody who signs in to the console.
/// </summary>
/// <remarks>
/// Until this existed there was one <c>X-Blinky-Operator</c> token standing for
/// everybody, so the audit trail could say a credential had been revoked and
/// never by whom, nothing expired, and withdrawing access from one person meant
/// withdrawing it from all of them. A system whose purpose is proving who holds
/// which credential could not say who was operating it.
/// <para>
/// Patch 0053a wanted operators to sign in with the smart cards this product
/// issues, and that is still the destination — see
/// docs/14-workstation-app-and-sign-in.md. It cannot be the way in, because a
/// card cannot be required to sign into the system that issues cards before it
/// has issued any. So: an account with a password and a second factor, and the
/// certificate as the upgrade.
/// </para>
/// </remarks>
public class OperatorAccount
{
    public virtual Guid Id { get; protected set; }

    /// <summary>Lower-case, unique. What the person types.</summary>
    public virtual string Username { get; set; } = string.Empty;

    public virtual string DisplayName { get; set; } = string.Empty;

    /// <summary>
    /// PBKDF2 parameters and hash in one self-describing string.
    /// </summary>
    /// <remarks>
    /// Self-describing so the cost can be raised later without a migration:
    /// a hash written today carries the iteration count it was made with, and
    /// verifying an old one still works while new ones get the new cost.
    /// </remarks>
    public virtual string PasswordHash { get; set; } = string.Empty;

    /// <summary>
    /// The shared secret behind the authenticator app's six digits, base32.
    /// </summary>
    /// <remarks>
    /// Null until the account enrols one. This is a bearer secret: anyone
    /// holding it can produce valid codes forever, which is why 0087 moves it
    /// behind the same envelope encryption the escrowed PUKs use. It is in the
    /// clear today and that is a named gap rather than an oversight.
    /// </remarks>
    public virtual string? TotpSecret { get; set; }

    /// <summary>
    /// When the second factor was proved for the first time.
    /// </summary>
    /// <remarks>
    /// Null means the account has a secret it has never demonstrated, or no
    /// secret at all. Either way it cannot finish signing in: a second factor
    /// that is optional until somebody gets round to it is a second factor
    /// nobody has.
    /// </remarks>
    public virtual DateTime? TotpConfirmedAt { get; set; }

    public virtual OperatorRole Role { get; set; } = OperatorRole.Operator;

    public virtual OperatorAccountState State { get; set; } = OperatorAccountState.Active;

    /// <summary>
    /// Consecutive failures since the last success.
    /// </summary>
    /// <remarks>
    /// A card gives an attacker three tries and then stops. An HTTP endpoint
    /// gives as many as the network allows unless something counts, so this
    /// counts.
    /// </remarks>
    public virtual int FailedAttempts { get; set; }

    public virtual DateTime? LockedUntil { get; set; }

    public virtual DateTime? LastSignInAt { get; set; }

    /// <summary>
    /// True while this is the account the deployment created for the first way
    /// in, and it has not yet been used.
    /// </summary>
    /// <remarks>
    /// The bootstrap closes after first use, which 0053d asked for: a password
    /// printed by an installer is a password in a terminal history, a screen
    /// recording and a support bundle, and it should buy exactly one sign-in
    /// during which a real one is set.
    /// </remarks>
    public virtual bool MustChangePassword { get; set; }

    public virtual DateTime CreatedAt { get; set; }

    public virtual DateTime UpdatedAt { get; set; }
}
