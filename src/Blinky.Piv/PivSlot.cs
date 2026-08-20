namespace Blinky.Piv;

/// <summary>
/// A PIV key slot and the data object its certificate lives in.
/// </summary>
/// <remarks>
/// The retired slots are here from the start: rolling a <see cref="KeyManagement"/>
/// key without keeping the old one destroys the user's mail archive, and that
/// is not recoverable after the fact. See docs/03-piv-layer.md.
/// </remarks>
public readonly record struct PivSlot(byte Id, string Name)
{
    /// <summary>9A - smart-card logon, the primary credential.</summary>
    public static readonly PivSlot Authentication = new(0x9A, "9A");

    /// <summary>9C - signing. PIN policy is Always by definition.</summary>
    public static readonly PivSlot DigitalSignature = new(0x9C, "9C");

    /// <summary>9D - encryption and S/MIME decryption.</summary>
    public static readonly PivSlot KeyManagement = new(0x9D, "9D");

    /// <summary>9E - physical access, no PIN.</summary>
    public static readonly PivSlot CardAuthentication = new(0x9E, "9E");

    /// <summary>F9 - the token's attestation key. Read-only.</summary>
    public static readonly PivSlot Attestation = new(0xF9, "F9");

    /// <summary>The four slots a credential is ever issued into.</summary>
    public static readonly IReadOnlyList<PivSlot> Credentials =
    [
        Authentication, DigitalSignature, KeyManagement, CardAuthentication,
    ];

    /// <summary>82 to 95 - old key management keys, kept so old mail still opens.</summary>
    public static IEnumerable<PivSlot> Retired()
    {
        for (var id = 0x82; id <= 0x95; id++)
        {
            yield return new PivSlot((byte)id, $"{id:X2}");
        }
    }

    /// <summary>
    /// The three-byte data object tag holding this slot's certificate, or null
    /// for slots that have none.
    /// </summary>
    public byte[]? CertificateObject => Id switch
    {
        0x9A => [0x5F, 0xC1, 0x05],
        0x9C => [0x5F, 0xC1, 0x0A],
        0x9D => [0x5F, 0xC1, 0x0B],
        0x9E => [0x5F, 0xC1, 0x01],
        // Retired slots run 5FC10D..5FC120 in slot order.
        >= 0x82 and <= 0x95 => [0x5F, 0xC1, (byte)(0x0D + (Id - 0x82))],
        _ => null,
    };

    public override string ToString() => Name;
}
