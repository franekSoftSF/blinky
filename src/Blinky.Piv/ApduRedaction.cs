namespace Blinky.Piv;

/// <summary>
/// Renders an APDU for a human without rendering the secret inside it.
/// </summary>
/// <remarks>
/// <para>
/// A failed transmit used to be reported with the whole command in hex, which
/// on a VERIFY reads
/// </para>
/// <code>
/// SCardTransmit(0020008008323538303235FFFF) failed: 0x80100068
/// </code>
/// <para>
/// and those twelve digits in the middle are the user's PIN in ASCII. That
/// message travelled into a job result, from there into the database, and
/// would have gone into a support bundle next. The PIN is not supposed to
/// exist anywhere but in the moment it is checked.
/// </para>
/// <para>
/// So the header survives — class, instruction, both parameters and the
/// length are what actually say which operation failed — and the body does
/// not. Redaction is by instruction rather than by inspecting the bytes,
/// because a rule that has to recognise a PIN will one day fail to.
/// </para>
/// </remarks>
public static class ApduRedaction
{
    /// <summary>
    /// Instructions whose data field carries something that must not be
    /// written down. Not a guess: each one is a command this library sends.
    /// </summary>
    private static readonly byte[] CarriesASecret =
    [
        0x20, // VERIFY - the PIN, and on slot 96 the biometric template match
        0x24, // CHANGE REFERENCE DATA - the old PIN and the new one, together
        0x2C, // RESET RETRY COUNTER - the PUK and the PIN it sets
        0x87, // GENERAL AUTHENTICATE - the management key witness and response
        0xDB, // PUT DATA - a new management key on its way to the card
    ];

    /// <summary>Hex, with the data field replaced when it holds a secret.</summary>
    public static string Describe(ReadOnlySpan<byte> apdu)
    {
        // Too short to have a data field, so there is nothing to hide and the
        // whole thing is worth seeing.
        if (apdu.Length <= 5)
        {
            return Convert.ToHexString(apdu);
        }

        var header = Convert.ToHexString(apdu[..5]);

        if (CarriesASecret.Contains(apdu[1]))
        {
            return $"{header} <{apdu.Length - 5} bytes withheld>";
        }

        // Everything else in full, up to a point: a certificate on its way to
        // a slot is two kilobytes, and two kilobytes of hex in an error
        // message is a way of hiding the error.
        const int Limit = 64;

        return apdu.Length - 5 <= Limit
            ? Convert.ToHexString(apdu)
            : $"{header}{Convert.ToHexString(apdu.Slice(5, Limit))}... "
              + $"({apdu.Length - 5} bytes)";
    }
}
