using Blinky.Api.Secrets;
using Blinky.Secrets;

namespace Blinky.UnitTests;

/// <summary>
/// The scheme that replaced using the configured KEK as an AES key directly.
/// </summary>
/// <remarks>
/// The old arrangement is the one shape a device cannot serve: using a key as a
/// cipher key means holding its bytes. Each envelope now gets its own key,
/// derived from a root the device holds, the token the envelope belongs to and
/// the nonce it will be used with.
/// </remarks>
public class PukEnvelopeTests
{
    private static readonly KeyRef Kek =
        new(KeyPurpose.PukKek, PukKekVersions.FirstProviderVersion);

    private static ConfigurationKeyProvider Provider()
    {
        var secret = new byte[32];
        Array.Fill(secret, (byte)0x77);

        return new ConfigurationKeyProvider(new Dictionary<KeyRef, byte[]>
        {
            [Kek] = secret,
            [new KeyRef(KeyPurpose.PukKek, 3)] = secret,
        });
    }

    private static byte[] Nonce(byte fill)
    {
        var nonce = new byte[12];
        Array.Fill(nonce, fill);
        return nonce;
    }

    /// <summary>
    /// The property that makes AES-GCM safe here: no two envelopes share a key,
    /// so no two can share a key and a nonce.
    /// </summary>
    [Fact]
    public void A_different_nonce_is_a_different_key()
    {
        using var provider = Provider();

        Assert.NotEqual(
            PukEnvelope.Key(provider, Kek, "puk|23673995", Nonce(0x01)),
            PukEnvelope.Key(provider, Kek, "puk|23673995", Nonce(0x02)));
    }

    /// <summary>
    /// A ciphertext moved to another token's row cannot open, because the
    /// associated data that authenticates it also derives the key that would
    /// have to open it.
    /// </summary>
    [Fact]
    public void A_different_token_is_a_different_key()
    {
        using var provider = Provider();

        Assert.NotEqual(
            PukEnvelope.Key(provider, Kek, "puk|23673995", Nonce(0x01)),
            PukEnvelope.Key(provider, Kek, "puk|29051525", Nonce(0x01)));
    }

    /// <summary>
    /// Two generations of the root give two different envelope keys even from
    /// identical material, so a rotation cannot silently be a no-op.
    /// </summary>
    [Fact]
    public void A_different_generation_is_a_different_key()
    {
        using var provider = Provider();

        Assert.NotEqual(
            PukEnvelope.Key(provider, Kek, "puk|23673995", Nonce(0x01)),
            PukEnvelope.Key(provider, new KeyRef(KeyPurpose.PukKek, 3), "puk|23673995",
                Nonce(0x01)));
    }

    /// <summary>
    /// The same envelope opens with the same key, which is the only reason any
    /// of this works.
    /// </summary>
    [Fact]
    public void The_same_envelope_derives_the_same_key()
    {
        using var provider = Provider();

        Assert.Equal(
            PukEnvelope.Key(provider, Kek, "puk|23673995", Nonce(0x05)),
            PukEnvelope.Key(provider, Kek, "puk|23673995", Nonce(0x05)));
    }

    [Fact]
    public void The_key_is_the_size_aes_256_needs()
    {
        using var provider = Provider();

        Assert.Equal(32, PukEnvelope.Key(provider, Kek, "puk|1", Nonce(0x01)).Length);
    }

    /// <summary>
    /// Version one is the raw configured KEK and is never a provider key. A
    /// deployment that configured it as one would be writing envelopes nothing
    /// could open.
    /// </summary>
    [Fact]
    public void Version_one_is_not_a_provider_generation()
    {
        Assert.Equal(1, PukKekVersions.Legacy);
        Assert.True(PukKekVersions.FirstProviderVersion > PukKekVersions.Legacy);
    }
}
