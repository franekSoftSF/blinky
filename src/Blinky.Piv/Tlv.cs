namespace Blinky.Piv;

/// <summary>
/// The two tag-length-value shapes the PIV applet uses: BER for data objects,
/// and a single-byte-length form for metadata responses.
/// </summary>
internal static class Tlv
{
    /// <summary>
    /// Parses BER-TLV, as used by data objects. Tolerant of a truncated final
    /// value: a short read should surface as a missing field rather than an
    /// exception from a parser.
    /// </summary>
    public static Dictionary<byte, byte[]> ParseBer(ReadOnlySpan<byte> data)
    {
        var result = new Dictionary<byte, byte[]>();
        var i = 0;

        while (i < data.Length)
        {
            var tag = data[i++];
            if (i >= data.Length)
            {
                break;
            }

            int length = data[i++];
            if (length is > 0x80 and <= 0x84)
            {
                var count = length - 0x80;
                if (i + count > data.Length)
                {
                    break;
                }

                length = 0;
                for (var k = 0; k < count; k++)
                {
                    length = (length << 8) | data[i++];
                }
            }
            else if (length == 0x80)
            {
                // Indefinite length: not used by PIV, and guessing would be worse.
                break;
            }

            if (i + length > data.Length)
            {
                length = data.Length - i;
            }

            result[tag] = data.Slice(i, length).ToArray();
            i += length;
        }

        return result;
    }

    /// <summary>Parses the single-byte-length form used by GET METADATA.</summary>
    public static Dictionary<byte, byte[]> ParseSimple(ReadOnlySpan<byte> data)
    {
        var result = new Dictionary<byte, byte[]>();
        var i = 0;

        while (i + 1 < data.Length)
        {
            var tag = data[i++];
            int length = data[i++];

            if (i + length > data.Length)
            {
                length = data.Length - i;
            }

            result[tag] = data.Slice(i, length).ToArray();
            i += length;
        }

        return result;
    }
}
