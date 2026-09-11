using System.Security.Cryptography;
using System.Text;
using Blinky.Api.Secrets;
using Blinky.Secrets;

namespace Blinky.UnitTests;

/// <summary>
/// The two promises docs/06-security.md makes about management keys, and the
/// third one the move behind a key provider had to keep: that no card changed.
/// </summary>
public class ManagementKeyDerivationTests
{
    private static byte[] Master(byte fill = 0x5A)
    {
        var master = new byte[32];
        Array.Fill(master, fill);
        return master;
    }

    private static ManagementKeyDerivation Derivation(byte fill = 0x5A, int version = 1) =>
        new(Provider(Master(fill), version), version);

    private static IKeyProvider Provider(byte[] master, int version = 1) =>
        new ConfigurationKeyProvider(new Dictionary<KeyRef, byte[]>
        {
            [new KeyRef(KeyPurpose.ManagementKeyMaster, version)] = master,
        });

    /// <summary>
    /// "One token's key opens one token."
    /// </summary>
    [Fact]
    public void Two_tokens_get_different_keys()
    {
        var derivation = Derivation();

        Assert.NotEqual(derivation.For(23673995), derivation.For(29051525));
    }

    /// <summary>
    /// And neighbouring serials are not near each other, which a naive
    /// concatenation would not guarantee.
    /// </summary>
    [Fact]
    public void Adjacent_serials_share_nothing()
    {
        var derivation = Derivation();

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
        Assert.Equal(Derivation().For(23673995), Derivation().For(23673995));
    }

    /// <summary>
    /// A different master gives a different key for the same token.
    /// </summary>
    [Fact]
    public void A_different_master_opens_nothing()
    {
        Assert.NotEqual(Derivation(0x11).For(23673995), Derivation(0x22).For(23673995));
    }

    [Fact]
    public void Long_enough_for_every_algorithm()
    {
        // AES-256 is the largest management key PIV defines.
        Assert.Equal(32, Derivation().For(1).Length);
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
        var derivation = new ManagementKeyDerivation(
            new ConfigurationKeyProvider(new Dictionary<KeyRef, byte[]>()), 1);

        Assert.False(derivation.IsConfigured);

        var refused = Assert.Throws<InvalidOperationException>(() => derivation.For(1));
        Assert.Contains("MANAGEMENT_KEY_MASTER", refused.Message);
    }

    /// <summary>
    /// <b>The card compatibility pin.</b> Every management key this deployment
    /// has ever written came out of one call to HKDF over the configured
    /// master. Moving the master behind a provider was allowed to change where
    /// the arithmetic happens and was not allowed to change its answer.
    /// </summary>
    /// <remarks>
    /// This is the test that makes a migration to a device possible at all. The
    /// extract half of HKDF cannot be performed by a token holding the master
    /// as a key, so the token holds the extract instead - and for a 32-byte
    /// output that is one HMAC block, which is exactly what HKDF would have
    /// produced. If this ever fails, every card in every deployment becomes
    /// unmanageable at the next enrolment, so it fails loudly and on purpose.
    /// </remarks>
    [Fact]
    public void The_values_are_the_ones_written_before_any_of_this_existed()
    {
        var master = Master();

        foreach (var serial in new long[] { 1, 23673995, 29051525 })
        {
            var before = HKDF.DeriveKey(HashAlgorithmName.SHA256, master,
                ManagementKeyDerivation.SecretLength, salt: null,
                Encoding.UTF8.GetBytes($"blinky/management-key/v1/{serial}"));

            Assert.Equal(before, Derivation().For(serial));
        }
    }

    /// <summary>
    /// A card diversified under an older master is still manageable while a
    /// newer one is what new cards get.
    /// </summary>
    /// <remarks>
    /// Rotation that cannot overlap is rotation nobody performs: the flag day
    /// is a job per token, and until it has run both generations have to work.
    /// </remarks>
    [Fact]
    public void An_older_generation_still_derives()
    {
        var provider = new ConfigurationKeyProvider(new Dictionary<KeyRef, byte[]>
        {
            [new KeyRef(KeyPurpose.ManagementKeyMaster, 1)] = Master(0x11),
            [new KeyRef(KeyPurpose.ManagementKeyMaster, 2)] = Master(0x22),
        });

        var derivation = new ManagementKeyDerivation(provider, version: 2);

        Assert.Equal(2, derivation.Version);

        var current = derivation.For(23673995);
        var older = derivation.For(23673995, generation: 1);

        Assert.NotEqual(current, older);

        // And the older one is what the version-one deployment would have
        // written, not merely something different.
        Assert.Equal(
            new ManagementKeyDerivation(provider, version: 1).For(23673995),
            older);
    }

    /// <summary>
    /// Asking for a generation the provider does not hold is a sentence, not a
    /// wrong key.
    /// </summary>
    [Fact]
    public void A_generation_that_was_never_provisioned_is_refused()
    {
        var derivation = Derivation();

        var refused = Assert.Throws<InvalidOperationException>(
            () => derivation.For(1, generation: 7));

        Assert.Contains("blinky/management-key/v7", refused.Message);
    }
}
