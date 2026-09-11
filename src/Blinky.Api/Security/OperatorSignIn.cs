using Blinky.Domain;
using Blinky.Domain.Entities;

namespace Blinky.Api.Security;

/// <summary>What happened, and what the caller has to do next.</summary>
public enum SignInOutcome
{
    /// <summary>
    /// Wrong name, wrong password, or a disabled account.
    /// </summary>
    /// <remarks>
    /// One outcome for all three on purpose. Telling somebody that a username
    /// exists but the password is wrong turns a guessing problem into two
    /// easier ones, and "this account is disabled" is the same disclosure in a
    /// politer sentence.
    /// </remarks>
    Refused,

    /// <summary>Too many failures. Says when, because a person needs to know.</summary>
    LockedOut,

    /// <summary>
    /// The password was right and it was the one the deployment generated.
    /// </summary>
    PasswordChangeRequired,

    /// <summary>The password was right and there is no second factor yet.</summary>
    TotpEnrolmentRequired,

    /// <summary>The password was right. Now the six digits.</summary>
    TotpRequired,

    /// <summary>Both factors, and nothing outstanding.</summary>
    SignedIn,
}

public sealed record SignInResult(SignInOutcome Outcome, OperatorAccount? Account = null,
    DateTime? LockedUntil = null);

/// <summary>
/// The order in which a console sign-in is allowed to succeed.
/// </summary>
/// <remarks>
/// Separated from the endpoints so it can be tested without a request, because
/// this is where the mistakes in an authentication feature actually live: the
/// order of the checks, what a failure counts towards, and what each refusal
/// tells somebody who is guessing.
/// </remarks>
public sealed class OperatorSignIn(Func<DateTime> clock)
{
    /// <summary>
    /// Consecutive failures before the account stops answering.
    /// </summary>
    /// <remarks>
    /// Five rather than three. A card gives three because each attempt costs
    /// somebody physical possession of it; a password is typed by people who
    /// mistype, and locking a console operator out during an incident is its
    /// own kind of outage.
    /// </remarks>
    public const int MaxFailedAttempts = 5;

    public static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);

    /// <summary>
    /// A hash of nothing anybody knows, for when the account does not exist.
    /// </summary>
    /// <remarks>
    /// Verified anyway, and the result thrown away. Without it a request for a
    /// name that exists takes a PBKDF2 derivation longer than one that does
    /// not, and the difference is measurable from outside - which is a way to
    /// enumerate accounts that needs no password at all.
    /// </remarks>
    private static readonly string DecoyHash =
        PasswordHash.Create(Guid.NewGuid().ToString("N"));

    /// <summary>
    /// The first factor. Mutates the account's counters and expects the caller
    /// to persist it.
    /// </summary>
    public SignInResult WithPassword(OperatorAccount? account, string password)
    {
        var now = clock();

        // Missing, disabled, or being guessed at - all of them still pay for a
        // derivation, so none of them is distinguishable by how long it took.
        if (account is null || account.State != OperatorAccountState.Active)
        {
            PasswordHash.Verify(password, account?.PasswordHash ?? DecoyHash);
            return new SignInResult(SignInOutcome.Refused);
        }

        if (account.LockedUntil is { } until && until > now)
        {
            // Checked before the password, so a locked account cannot be used
            // as an oracle for whether a guess was right.
            return new SignInResult(SignInOutcome.LockedOut, LockedUntil: until);
        }

        if (!PasswordHash.Verify(password, account.PasswordHash))
        {
            account.FailedAttempts++;
            account.UpdatedAt = now;

            if (account.FailedAttempts >= MaxFailedAttempts)
            {
                account.LockedUntil = now.Add(LockoutDuration);
                account.FailedAttempts = 0;

                return new SignInResult(SignInOutcome.LockedOut,
                    LockedUntil: account.LockedUntil);
            }

            return new SignInResult(SignInOutcome.Refused);
        }

        account.FailedAttempts = 0;
        account.LockedUntil = null;
        account.UpdatedAt = now;

        if (account.MustChangePassword)
        {
            return new SignInResult(SignInOutcome.PasswordChangeRequired, account);
        }

        if (account.TotpConfirmedAt is null)
        {
            return new SignInResult(SignInOutcome.TotpEnrolmentRequired, account);
        }

        return new SignInResult(SignInOutcome.TotpRequired, account);
    }

    /// <summary>
    /// The second factor. Only ever reached by an account that has already
    /// passed the first one in this exchange.
    /// </summary>
    /// <remarks>
    /// A wrong code counts towards the same lockout as a wrong password.
    /// Counting them separately would leave somebody who has the password an
    /// unbounded number of guesses at six digits, which is a million and
    /// therefore not many.
    /// </remarks>
    public SignInResult WithTotp(OperatorAccount account, string code)
    {
        ArgumentNullException.ThrowIfNull(account);

        var now = clock();

        if (account.LockedUntil is { } until && until > now)
        {
            return new SignInResult(SignInOutcome.LockedOut, LockedUntil: until);
        }

        if (string.IsNullOrEmpty(account.TotpSecret)
            || !Totp.Verify(account.TotpSecret, code, now))
        {
            account.FailedAttempts++;
            account.UpdatedAt = now;

            if (account.FailedAttempts >= MaxFailedAttempts)
            {
                account.LockedUntil = now.Add(LockoutDuration);
                account.FailedAttempts = 0;

                return new SignInResult(SignInOutcome.LockedOut,
                    LockedUntil: account.LockedUntil);
            }

            return new SignInResult(SignInOutcome.Refused);
        }

        account.FailedAttempts = 0;
        account.LockedUntil = null;
        account.LastSignInAt = now;
        account.UpdatedAt = now;

        // First successful use of a secret is what confirms it. Until then the
        // account has a secret it has never demonstrated, which is not a second
        // factor - it is a string in a column.
        account.TotpConfirmedAt ??= now;

        return new SignInResult(SignInOutcome.SignedIn, account);
    }

    /// <summary>
    /// Replaces the password, and closes the bootstrap if this was it.
    /// </summary>
    public void SetPassword(OperatorAccount account, string password)
    {
        ArgumentNullException.ThrowIfNull(account);

        account.PasswordHash = PasswordHash.Create(password);
        account.MustChangePassword = false;
        account.UpdatedAt = clock();
    }
}
