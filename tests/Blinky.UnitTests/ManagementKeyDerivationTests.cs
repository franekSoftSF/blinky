using Blinky.Api.Secrets;

namespace Blinky.UnitTests;

/// <summary>
/// The two promises docs/06-security.md makes about management keys.
/// </summary>
public class ManagementKeyDerivationTests
{
    private static byte[] Master(byte fill = 0x5A)
    {
        var master = new byte[32];
        Array.Fill(master, fill);
        return master;
    }

    /// <summary>
    /// "One token's key opens one token."
    /// </summary>
    [Fact]
    public void Two_tokens_get_different_keys()
    {
        var derivation = new ManagementKeyDerivation(Master());

        Assert.NotEqual(derivation.For(23673995), derivation.For(29051525));
    }

    /// <summary>
    /// And neighbouring serials are not near each other, which a naive
    /// concatenation would not guarantee.
    /// </summary>
    [Fact]
    public void Adjacent_serials_share_nothing()
    {
        var derivation = new ManagementKeyDerivation(Master());

        var a = derivation.For(1);
        var b = derivation.For(12);
        var c = derivation.For(2);

        Assert.NotEqual(a, b);
        Assert.NotEqual(a, c);
        Assert.NotEqual(b, c);
    }

    /// <summary>
    /// "Derived, not stored" only works if the derivation is reproducible.
    /// </summary>
    /// <remarks>
    /// Nothing writes a management key down, so this function is the only way
    /// back to a card. If it were not deterministic, the first card issued
    /// would be the last one anybody could manage.
    /// </remarks>
    [Fact]
    public void The_same_master_and_serial_give_the_same_key()
    {
        Assert.Equal(
            new ManagementKeyDerivation(Master()).For(23673995),
            new ManagementKeyDerivation(Master()).For(23673995));
    }

    /// <summary>
    /// A different master gives a different key for the same token.
    /// </summary>
    [Fact]
    public void A_different_master_opens_nothing()
    {
        Assert.NotEqual(
            new ManagementKeyDerivation(Master(0x11)).For(23673995),
            new ManagementKeyDerivation(Master(0x22)).For(23673995));
    }

    [Fact]
    public void Long_enough_for_every_algorithm()
    {
        // AES-256 is the largest management key PIV defines.
        Assert.Equal(32, new ManagementKeyDerivation(Master()).For(1).Length);
        Assert.Equal(32, ManagementKeyDerivation.SecretLength);
    }

    /// <summary>
    /// No master is a deployment that has not set one up, said plainly.
    /// </summary>
    /// <remarks>
    /// Every card issued so far is in that state. It should read as a
    /// configuration that is missing, not as a card that is broken.
    /// </remarks>
    [Fact]
    public void Without_a_master_it_says_so()
    {
        var derivation = new ManagementKeyDerivation([]);

        Assert.False(derivation.IsConfigured);

        var refused = Assert.Throws<InvalidOperationException>(() => derivation.For(1));
        Assert.Contains("MANAGEMENT_KEY_MASTER", refused.Message);
    }
}
