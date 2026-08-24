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
    /// <remarks>
    /// Tags may be more than one byte, and PIV uses one that is: the public
    /// key template a card returns from GENERATE ASYMMETRIC KEY PAIR is 7F49.
    /// In BER a tag whose low five bits are all ones continues into the bytes
    /// that follow, so 7F 49 is a single tag and not a tag followed by a
    /// length of 0x49.
    ///
    /// Reading it as the latter went unnoticed for a long time because it
    /// happens to work for ECC. There, 0x49 overruns the buffer, the clamp
    /// below trims the value to what is left, and the caller's [1..] then
    /// skips exactly the one byte that needed skipping. An RSA response is
    /// longer, nothing overruns, and the parser walks off into the middle of
    /// the modulus - reporting a missing tag 81 for a key sitting right there
    /// in the bytes.
    ///
    /// Keys are the whole tag, so 7F49 is 0x7F49 rather than 0x7F.
    /// </remarks>
    public static Dictionary<int, byte[]> ParseBer(ReadOnlySpan<byte> data)
    {
        var result = new Dictionary<int, byte[]>();
        var i = 0;

        while (i < data.Length)
        {
            int tag = data[i++];

            // A tag whose low five bits are all ones continues into the next
            // byte, and keeps going while the high bit is set.
            if ((tag & 0x1F) == 0x1F)
            {
                while (i < data.Length)
                {
                    var next = data[i++];
                    tag = (tag << 8) | next;

                    if ((next & 0x80) == 0)
                    {
                        break;
                    }
                }
            }

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
