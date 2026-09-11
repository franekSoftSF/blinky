using System.Security.Cryptography;
using System.Text;
using Blinky.Api.Security;

namespace Blinky.UnitTests;

/// <summary>
/// The two pieces of cryptography behind signing in to the console.
/// </summary>
/// <remarks>
/// Both are written here rather than taken from a package, which is only
/// defensible if they are checked rather than trusted. The TOTP cases are the
/// vectors from RFC 6238 appendix B, so anybody can tell whether this
/// implementation is right without reading it.
/// </remarks>
public class OperatorSignInTests
{
    // "12345678901234567890" - the seed RFC 6238 appendix B uses for SHA-1.
    private static byte[] RfcSeed => Encoding.ASCII.GetBytes("12345678901234567890");

    [Theory]
    [InlineData(59L, "94287082")]
    [InlineData(1111111109L, "07081804")]
    [InlineData(1111111111L, "14050471")]
    [InlineData(1234567890L, "89005924")]
    [InlineData(2000000000L, "69279037")]
    [InlineData(20000000000L, "65353130")]
    public void Rfc6238_appendix_b(long unixSeconds, string expected)
    {
        var counter = Totp.CounterAt(DateTimeOffset.FromUnixTimeSeconds(unixSeconds));

        Assert.Equal(expected, Totp.Compute(RfcSeed, counter, digits: 8));
    }

    [Fact]
    public void A_code_is_accepted_in_its_own_step_and_one_either_side()
    {
        var secret = Totp.NewSecret();
        var key = Totp.FromBase32(secret);
        var now = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000);
        var counter = Totp.CounterAt(now);

        foreach (var step in new[] { -1L, 0L, 1L })
        {
            Assert.True(Totp.Verify(secret, Totp.Compute(key, counter + step), now),
                $"the code from step {step} should be accepted with one step of drift");
        }

        Assert.False(Totp.Verify(secret, Totp.Compute(key, counter + 2), now),
            "two steps away is outside a stated tolerance of one");
    }

    /// <summary>
    /// Drift is a parameter and the default is narrow.
    /// </summary>
    /// <remarks>
    /// Each step widens the window in both directions, so the default of one
    /// already means a code lives ninety seconds. Anything more generous is a
    /// decision somebody should have to type.
    /// </remarks>
    [Fact]
    public void Drift_tolerance_is_stated_rather_than_generous()
    {
        var secret = Totp.NewSecret();
        var key = Totp.FromBase32(secret);
        var now = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000);
        var far = Totp.Compute(key, Totp.CounterAt(now) + 3);

        Assert.False(Totp.Verify(secret, far, now));
        Assert.True(Totp.Verify(secret, far, now, driftSteps: 3));
    }

    [Theory]
    [InlineData("")]
    [InlineData("    ")]
    [InlineData("12345")]
    [InlineData("1234567")]
    [InlineData("abcdef")]
    [InlineData("12 34 56")]
    public void A_code_that_is_not_six_digits_is_refused_without_a_hash(string code)
    {
        Assert.False(Totp.Verify(Totp.NewSecret(), code,
            DateTimeOffset.FromUnixTimeSeconds(1_700_000_000)));
    }

    [Fact]
    public void Base32_round_trips()
    {
        var data = RandomNumberGenerator.GetBytes(20);

        Assert.Equal(data, Totp.FromBase32(Totp.ToBase32(data)));
    }

    /// <summary>
    /// The provisioning URI names the system, twice.
    /// </summary>
    /// <remarks>
    /// Applications that read only the label and applications that read the
    /// parameter both have to end up showing which system an account belongs
    /// to. One entry in a list saying only a username is an entry nobody can
    /// place a year later.
    /// </remarks>
    [Fact]
    public void The_provisioning_uri_says_what_it_is_for()
    {
        var uri = Totp.ProvisioningUri("Blinky", "superadmin@blinky.lab", "ABCDEFGH");

        Assert.StartsWith("otpauth://totp/Blinky:", uri, StringComparison.Ordinal);
        Assert.Contains("issuer=Blinky", uri, StringComparison.Ordinal);
        Assert.Contains("secret=ABCDEFGH", uri, StringComparison.Ordinal);
        Assert.Contains("digits=6", uri, StringComparison.Ordinal);
        Assert.Contains("period=30", uri, StringComparison.Ordinal);
    }

    [Fact]
    public void A_password_verifies_against_its_own_hash_and_nothing_else()
    {
        var stored = PasswordHash.Create("correct horse battery staple");

        Assert.True(PasswordHash.Verify("correct horse battery staple", stored));
        Assert.False(PasswordHash.Verify("correct horse battery stapl", stored));
        Assert.False(PasswordHash.Verify("Correct horse battery staple", stored));
        Assert.False(PasswordHash.Verify(string.Empty, stored));
    }

    /// <summary>
    /// Two accounts with the same password do not share a hash.
    /// </summary>
    /// <remarks>
    /// Which is what the salt is for, and the cheapest way to notice it has
    /// been dropped: without it, equal hashes in a stolen table say which
    /// accounts to attack once rather than one at a time.
    /// </remarks>
    [Fact]
    public void The_same_password_hashes_differently_every_time()
    {
        var first = PasswordHash.Create("same password");
        var second = PasswordHash.Create("same password");

        Assert.NotEqual(first, second);
        Assert.True(PasswordHash.Verify("same password", first));
        Assert.True(PasswordHash.Verify("same password", second));
    }

    [Fact]
    public void The_stored_form_carries_the_cost_it_was_made_with()
    {
        var cheap = PasswordHash.Create("password", iterations: 1_000);

        Assert.StartsWith("pbkdf2-sha256$1000$", cheap, StringComparison.Ordinal);
        Assert.True(PasswordHash.Verify("password", cheap));

        // Still verifiable, and still known to be behind - which is what lets
        // the cost be raised without locking anybody out.
        Assert.True(PasswordHash.NeedsRehash(cheap));
        Assert.False(PasswordHash.NeedsRehash(PasswordHash.Create("password")));
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-a-hash")]
    [InlineData("pbkdf2-sha256$notanumber$c2FsdA==$aGFzaA==")]
    [InlineData("pbkdf2-sha256$1000$not base64$aGFzaA==")]
    [InlineData("argon2id$1000$c2FsdA==$aGFzaA==")]
    [InlineData("pbkdf2-sha256$0$c2FsdA==$aGFzaA==")]
    public void A_stored_value_that_does_not_parse_is_a_refusal_not_a_crash(string stored)
    {
        Assert.False(PasswordHash.Verify("password", stored));
    }
}
