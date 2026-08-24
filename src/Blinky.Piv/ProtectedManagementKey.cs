namespace Blinky.Piv;

/// <summary>
/// The management key some cards keep in the PRINTED object, behind the PIN.
/// </summary>
/// <remarks>
/// Nothing in PIV describes this. It is Yubico's convention, and it is the one
/// that matters in practice: the YubiKey minidriver takes ownership of a card
/// when it is installed - random management key, stored here, PUK blocked - and
/// that driver is what makes smart-card logon work on Windows. So a card that
/// can log on is a card whose management key lives here, and a CMS that only
/// knows the factory key can touch such a card exactly once, before the
/// workstation is set up.
///
/// Separated from the reading so the encoding can be tested without a reader.
/// </remarks>
public static class ProtectedManagementKey
{
    /// <summary>Yubico's wrapper tag inside the PRINTED object.</summary>
    private const byte ProtectedData = 0x88;

    /// <summary>The tag holding the key itself.</summary>
    private const byte Key = 0x89;

    /// <summary>
    /// The key inside a PRINTED object, or null if it holds something else.
    /// </summary>
    /// <remarks>
    /// Null rather than an exception for anything unrecognised. The object is
    /// meant for what is printed on the face of a card, and a card really may
    /// hold that; refusing to work with such a card would be reading a
    /// convention as a requirement.
    /// </remarks>
    public static ManagementKey? Parse(byte[] printedObject, PivAlgorithm algorithm)
    {
        if (printedObject.Length == 0)
        {
            return null;
        }

        var outer = Tlv.ParseBer(printedObject);

        var body = outer.TryGetValue(0x53, out var wrapped)
            ? Tlv.ParseBer(wrapped)
            : outer;

        if (!body.TryGetValue(ProtectedData, out var protectedData))
        {
            return null;
        }

        if (!Tlv.ParseBer(protectedData).TryGetValue(Key, out var key) || key.Length == 0)
        {
            return null;
        }

        try
        {
            return new ManagementKey(key, algorithm);
        }
        catch (ArgumentException)
        {
            // A length the algorithm does not take. The card holds something
            // in these tags that is not a key for it, which is not ours to
            // interpret further.
            return null;
        }
    }
}
