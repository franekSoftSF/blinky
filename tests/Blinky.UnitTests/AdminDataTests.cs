using Blinky.Piv;

namespace Blinky.UnitTests;

/// <summary>
/// The flags object a YubiKey keeps outside the PIV standard.
/// </summary>
/// <remarks>
/// Blinky touches one bit in it: the one saying the management key is kept
/// behind the PIN. The object holds other things - a salt for Yubico's
/// derived-key scheme, a timestamp - that belong to whoever put them there,
/// and this code cannot recreate them.
///
/// Writing the bit matters because the key in PRINTED is only half the fact.
/// Yubico's tools read this object to decide whether a card is managed, so a
/// card with the key and without the bit reads as a card whose management key
/// nobody knows - and the minidriver takes such a card over, which is the
/// thing writing the key was meant to prevent.
/// </remarks>
public class AdminDataTests
{
    private const byte Wrapper = 0x80;
    private const byte Flags = 0x81;
    private const byte Salt = 0x82;
    private const byte Protected = 0x02;
    private const byte PukBlocked = 0x01;

    /// <summary>Builds an ADMIN DATA body as the card stores it.</summary>
    private static byte[] AdminData(params (byte Tag, byte[] Value)[] fields)
    {
        var inner = new List<byte>();

        foreach (var (tag, value) in fields)
        {
            inner.Add(tag);
            inner.Add((byte)value.Length);
            inner.AddRange(value);
        }

        var body = new List<byte> { Wrapper, (byte)inner.Count };
        body.AddRange(inner);

        var outer = new List<byte> { 0x53, (byte)body.Count };
        outer.AddRange(body);

        return [.. outer];
    }

    /// <summary>The tags are the constants the production code writes.</summary>
    [Fact]
    public void The_object_and_its_tags_are_what_yubico_uses()
    {
        Assert.Equal([0x5F, 0xFF, 0x00], PivCardObjects.AdminData);
        Assert.Equal(Wrapper, PivCardObjects.AdminDataWrapper);
        Assert.Equal(Flags, PivCardObjects.AdminFlagsTag);
        Assert.Equal(Protected, PivCardObjects.AdminFlagManagementKeyProtected);
        Assert.Equal(PukBlocked, PivCardObjects.AdminFlagPukBlocked);
    }

    /// <summary>
    /// A card that already has flags keeps them.
    /// </summary>
    /// <remarks>
    /// The bit is set, not assigned. A card whose PUK was deliberately blocked
    /// records that in the same byte, and replacing the byte would tell every
    /// tool that the PUK is usable again.
    /// </remarks>
    [Fact]
    public void Setting_the_bit_leaves_the_others_alone()
    {
        var parsed = Tlv.ParseBer(AdminData((Flags, [PukBlocked])));
        var body = Tlv.ParseBer(parsed[0x53]);
        var fields = Tlv.ParseBer(body[Wrapper]);

        var updated = (byte)(fields[Flags][0] | Protected);

        Assert.Equal(PukBlocked | Protected, updated);
        Assert.NotEqual(Protected, updated);
    }

    /// <summary>
    /// And fields this code knows nothing about survive.
    /// </summary>
    [Fact]
    public void Other_fields_survive_the_round_trip()
    {
        var salt = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF };

        var parsed = Tlv.ParseBer(AdminData((Flags, [0x00]), (Salt, salt)));
        var fields = Tlv.ParseBer(Tlv.ParseBer(parsed[0x53])[Wrapper]);

        Assert.Equal(salt, fields[Salt]);
        Assert.True(fields.ContainsKey(Flags));
    }

    /// <summary>An object with no flags field yet is not an error.</summary>
    [Fact]
    public void A_card_with_no_flags_starts_from_none()
    {
        var fields = Tlv.ParseBer(Tlv.ParseBer(
            Tlv.ParseBer(AdminData((Salt, [0x01])))[0x53])[Wrapper]);

        Assert.False(fields.ContainsKey(Flags));
    }
}
