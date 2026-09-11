using Blinky.Api.Security;
using Blinky.Domain;
using Blinky.Domain.Entities;

namespace Blinky.UnitTests;

/// <summary>
/// The order the checks run in, which is where an authentication feature goes
/// wrong.
/// </summary>
/// <remarks>
/// Not what a password hash does - that is
/// <see cref="OperatorSignInTests"/> - but what a refusal reveals, what a
/// failure counts towards, and what cannot be skipped.
/// </remarks>
public class OperatorSignInOrderTests
{
    private DateTime now = new(2026, 9, 11, 20, 0, 0, DateTimeKind.Utc);

    private OperatorSignIn SignIn() => new(() => now);

    private static OperatorAccount Account(string password = "a good password",
        bool mustChange = false, string? totpSecret = null, bool totpConfirmed = false) =>
        new()
        {
            Username = "superadmin",
            DisplayName = "Super Admin",
            PasswordHash = PasswordHash.Create(password, iterations: 1_000),
            MustChangePassword = mustChange,
            TotpSecret = totpSecret,
            TotpConfirmedAt = totpConfirmed ? new DateTime(2026, 9, 1, 0, 0, 0, DateTimeKind.Utc) : null,
            Role = OperatorRole.Administrator,
            State = OperatorAccountState.Active,
        };

    /// <summary>
    /// A password alone never finishes a sign-in.
    /// </summary>
    /// <remarks>
    /// The whole point of 0086: a second factor that is optional until somebody
    /// gets round to it is a second factor nobody has. An account with no
    /// secret is sent to enrol one rather than let through.
    /// </remarks>
    [Fact]
    public void The_password_alone_is_never_enough()
    {
        var withoutSecret = SignIn().WithPassword(Account(), "a good password");
        Assert.Equal(SignInOutcome.TotpEnrolmentRequired, withoutSecret.Outcome);

        var withSecret = SignIn().WithPassword(
            Account(totpSecret: Totp.NewSecret(), totpConfirmed: true), "a good password");
        Assert.Equal(SignInOutcome.TotpRequired, withSecret.Outcome);
    }

    /// <summary>
    /// The bootstrap password buys one sign-in, during which a real one is set.
    /// </summary>
    [Fact]
    public void The_bootstrap_password_leads_to_a_change_and_closes_after_it()
    {
        var account = Account("printed-by-the-installer", mustChange: true);
        var signIn = SignIn();

        Assert.Equal(SignInOutcome.PasswordChangeRequired,
            signIn.WithPassword(account, "printed-by-the-installer").Outcome);

        signIn.SetPassword(account, "one nobody generated");

        Assert.False(account.MustChangePassword);
        Assert.Equal(SignInOutcome.Refused,
            signIn.WithPassword(account, "printed-by-the-installer").Outcome);
        Assert.Equal(SignInOutcome.TotpEnrolmentRequired,
            signIn.WithPassword(account, "one nobody generated").Outcome);
    }

    /// <summary>
    /// A name that exists and one that does not are refused identically.
    /// </summary>
    [Fact]
    public void A_missing_account_and_a_wrong_password_look_the_same()
    {
        Assert.Equal(SignInOutcome.Refused, SignIn().WithPassword(null, "anything").Outcome);
        Assert.Equal(SignInOutcome.Refused,
            SignIn().WithPassword(Account(), "not the password").Outcome);

        var disabled = Account();
        disabled.State = OperatorAccountState.Disabled;

        Assert.Equal(SignInOutcome.Refused,
            SignIn().WithPassword(disabled, "a good password").Outcome);
    }

    [Fact]
    public void Five_wrong_passwords_lock_the_account_for_fifteen_minutes()
    {
        var account = Account();
        var signIn = SignIn();

        for (var attempt = 1; attempt < OperatorSignIn.MaxFailedAttempts; attempt++)
        {
            Assert.Equal(SignInOutcome.Refused, signIn.WithPassword(account, "wrong").Outcome);
        }

        var locked = signIn.WithPassword(account, "wrong");

        Assert.Equal(SignInOutcome.LockedOut, locked.Outcome);
        Assert.Equal(now.Add(OperatorSignIn.LockoutDuration), locked.LockedUntil);

        // And the right password does not get past it, or the lockout would be
        // a delay for the wrong person only.
        Assert.Equal(SignInOutcome.LockedOut,
            signIn.WithPassword(account, "a good password").Outcome);

        now = now.Add(OperatorSignIn.LockoutDuration).AddSeconds(1);

        Assert.Equal(SignInOutcome.TotpEnrolmentRequired,
            signIn.WithPassword(account, "a good password").Outcome);
    }

    /// <summary>
    /// A wrong code costs the same as a wrong password.
    /// </summary>
    /// <remarks>
    /// Counting them separately would leave somebody holding the password an
    /// unbounded number of guesses at six digits, which is a million and
    /// therefore not many.
    /// </remarks>
    [Fact]
    public void Wrong_codes_count_towards_the_same_lockout()
    {
        var account = Account(totpSecret: Totp.NewSecret(), totpConfirmed: true);
        var signIn = SignIn();

        Assert.Equal(SignInOutcome.TotpRequired,
            signIn.WithPassword(account, "a good password").Outcome);

        for (var attempt = 1; attempt < OperatorSignIn.MaxFailedAttempts; attempt++)
        {
            Assert.Equal(SignInOutcome.Refused, signIn.WithTotp(account, "000000").Outcome);
        }

        Assert.Equal(SignInOutcome.LockedOut, signIn.WithTotp(account, "000000").Outcome);
    }

    [Fact]
    public void A_correct_code_finishes_the_sign_in_and_records_it()
    {
        var secret = Totp.NewSecret();
        var account = Account(totpSecret: secret, totpConfirmed: true);
        var signIn = SignIn();

        signIn.WithPassword(account, "a good password");

        var code = Totp.Compute(Totp.FromBase32(secret), Totp.CounterAt(now));
        var result = signIn.WithTotp(account, code);

        Assert.Equal(SignInOutcome.SignedIn, result.Outcome);
        Assert.Equal(now, account.LastSignInAt);
        Assert.Equal(0, account.FailedAttempts);
    }

    /// <summary>
    /// A secret becomes a second factor the first time it is demonstrated.
    /// </summary>
    /// <remarks>
    /// Until then it is a string in a column that nobody has proved they can
    /// produce codes from - which is exactly the situation where an operator
    /// scans a code, loses the telephone, and discovers it at the worst moment.
    /// </remarks>
    [Fact]
    public void Enrolment_is_confirmed_by_use_and_not_by_storing_a_secret()
    {
        var secret = Totp.NewSecret();
        var account = Account(totpSecret: secret);
        var signIn = SignIn();

        Assert.Null(account.TotpConfirmedAt);
        Assert.Equal(SignInOutcome.TotpEnrolmentRequired,
            signIn.WithPassword(account, "a good password").Outcome);

        var code = Totp.Compute(Totp.FromBase32(secret), Totp.CounterAt(now));

        Assert.Equal(SignInOutcome.SignedIn, signIn.WithTotp(account, code).Outcome);
        Assert.Equal(now, account.TotpConfirmedAt);

        // And the next sign-in asks for a code rather than for enrolment again.
        Assert.Equal(SignInOutcome.TotpRequired,
            signIn.WithPassword(account, "a good password").Outcome);
    }

    [Fact]
    public void An_account_with_no_secret_cannot_pass_the_second_factor()
    {
        var account = Account();

        Assert.Equal(SignInOutcome.Refused, SignIn().WithTotp(account, "000000").Outcome);
    }

    [Fact]
    public void A_success_clears_what_the_failures_counted()
    {
        var account = Account();
        var signIn = SignIn();

        signIn.WithPassword(account, "wrong");
        signIn.WithPassword(account, "wrong");
        Assert.Equal(2, account.FailedAttempts);

        signIn.WithPassword(account, "a good password");
        Assert.Equal(0, account.FailedAttempts);
    }
}
