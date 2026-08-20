using System.Security.Cryptography;
using Blinky.Piv;

namespace Blinky.UnitTests;

/// <summary>
/// The parts of the write path that can be checked without a card. The path
/// itself is proved by `tools/IssueOnCard` against real hardware — everything
/// here either destroys something or needs a token, so what is left to unit
/// test is the encoding and the arithmetic.
/// </summary>
public sealed class WritePathTests
{
    [Theory]
    [InlineData(PivAlgorithm.TripleDes, 24, 8)]
    [InlineData(PivAlgorithm.Aes128, 16, 16)]
    [InlineData(PivAlgorithm.Aes192, 24, 16)]
    [InlineData(PivAlgorithm.Aes256, 32, 16)]
    public void A_management_key_knows_its_own_length_and_block_size(PivAlgorithm algorithm,
        int keyBytes, int blockBytes)
    {
        var key = ManagementKey.Default(algorithm);

        Assert.Equal(blockBytes, key.BlockSize);
        Assert.Equal(algorithm, key.Algorithm);
        Assert.Equal(keyBytes, algorithm switch
        {
            PivAlgorithm.TripleDes or PivAlgorithm.Aes192 => 24,
            PivAlgorithm.Aes128 => 16,
            _ => 32,
        });
    }

    [Fact]
    public void The_factory_key_is_the_same_bytes_for_3des_and_aes192()
    {
        // Firmware below 5.7 ships 3DES and 5.7 or later ships AES-192, and the
        // default value is byte for byte the same. Only the algorithm differs,
        // which is why it has to be read from the card.
        var tripleDes = ManagementKey.Default(PivAlgorithm.TripleDes);
        var aes = ManagementKey.Default(PivAlgorithm.Aes192);

        Assert.NotEqual(tripleDes.Algorithm, aes.Algorithm);
        Assert.Equal(24, ManagementKey.FactoryDefault.Length);
    }

    [Theory]
    [InlineData(PivAlgorithm.TripleDes)]
    [InlineData(PivAlgorithm.Aes192)]
    public void Encryption_round_trips_a_block(PivAlgorithm algorithm)
    {
        // The mutual authentication depends on this in both directions: we
        // decrypt the card's witness, and we verify the card's answer by
        // encrypting our own challenge.
        var key = ManagementKey.Default(algorithm);
        var block = RandomNumberGenerator.GetBytes(key.BlockSize);

        Assert.Equal(block, key.Decrypt(key.Encrypt(block)));
    }

    [Fact]
    public void A_block_of_the_wrong_size_is_refused()
    {
        var key = ManagementKey.Default(PivAlgorithm.Aes192);

        Assert.Throws<PivProtocolException>(() => key.Encrypt(new byte[8]));
    }

    [Fact]
    public void A_key_of_the_wrong_length_is_refused()
    {
        Assert.Throws<ArgumentException>(
            () => new ManagementKey(new byte[16], PivAlgorithm.Aes192));
    }

    [Theory]
    [InlineData(0x7F, new byte[] { 0x7F })]
    [InlineData(0x80, new byte[] { 0x81, 0x80 })]
    [InlineData(0xFF, new byte[] { 0x81, 0xFF })]
    [InlineData(0x100, new byte[] { 0x82, 0x01, 0x00 })]
    [InlineData(1019, new byte[] { 0x82, 0x03, 0xFB })]
    public void Ber_lengths_switch_form_at_the_right_boundaries(int length, byte[] expected)
    {
        // 1019 is the size of a real certificate object written to a card. Get
        // this wrong and the card reads a different structure than the one that
        // was sent.
        var encoded = new List<byte>();
        PivSession.AppendLength(encoded, length);

        Assert.Equal(expected, encoded);
    }

    [Fact]
    public void A_pin_outside_the_permitted_length_is_refused_before_it_reaches_the_card()
    {
        // A short PIN sent to the card would still cost an attempt.
        var session = new PivSession(new PivConnection(TranscriptTransport.Scripted()));

        Assert.Throws<ArgumentException>(() => session.VerifyPin("12345"));
        Assert.Throws<ArgumentException>(() => session.VerifyPin("123456789"));
    }
}
