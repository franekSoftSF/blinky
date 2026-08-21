using System.Security.Cryptography;

namespace Blinky.Piv;

/// <summary>
/// The two data objects a card needs before Windows will use it, and their
/// contents.
/// </summary>
/// <remarks>
/// <para>
/// A certificate in slot 9A is not enough. Windows drives a PIV card through
/// its inbox minidriver, and that minidriver enumerates key containers from
/// the Card Capability Container and identifies the card by its Cardholder
/// Unique Identifier. With either missing it finds the certificate, cannot
/// associate a container with it, and returns <c>NTE_BAD_KEYSET</c> - "the
/// keyset does not exist" - for a key that is sitting right there.
/// </para>
/// <para>
/// A YubiKey leaves the factory without them, and <c>ykman piv reset</c>
/// removes them again. So provisioning has to write them; every other PIV
/// provisioning tool does, which is why this is invisible until you write your
/// own.
/// </para>
/// <para>
/// Observed on BY-WIN-CLIENT01, 21 August 2026: <c>certutil -scinfo</c> built
/// the whole chain from the card, printed the subject and the UPN, and then
/// failed with <c>0x80090016</c>. The card had a certificate, a key, and no
/// CHUID.
/// </para>
/// <para>
/// Neither object is a secret and neither is signed here. The issuer signature
/// field of a CHUID exists for FIPS 201 credentialing, where a federal
/// issuer's signature over the identifiers is the point; nothing in this
/// deployment consumes it, and writing an unsigned one is what every other
/// tool in this space does.
/// </para>
/// </remarks>
public static class PivCardObjects
{
    /// <summary>Cardholder Unique Identifier, <c>5F C1 02</c>.</summary>
    public static readonly byte[] CardholderUniqueIdentifier = [0x5F, 0xC1, 0x02];

    /// <summary>Card Capability Container, <c>5F C1 07</c>.</summary>
    public static readonly byte[] CardCapabilityContainer = [0x5F, 0xC1, 0x07];

    /// <summary>
    /// Builds a CHUID. The GUID is fresh, and it is the only part that varies.
    /// </summary>
    /// <param name="expires">
    /// The CHUID's own expiry, which is not the certificate's. Written as
    /// YYYYMMDD. A card whose CHUID has expired is refused by some readers
    /// while its certificate is still perfectly good, so this wants to be well
    /// beyond anything the card will hold.
    /// </param>
    public static byte[] BuildChuid(DateOnly expires)
    {
        var guid = new byte[16];
        RandomNumberGenerator.Fill(guid);

        var chuid = new List<byte>();

        // 30 - FASC-N. Twenty-five bytes of BCD identifying a federal agency,
        // person and credential. Nothing outside that world reads it, and
        // there is no agency here to assign one, so this is the placeholder
        // every non-federal issuer writes.
        chuid.AddRange([0x30, 0x19]);
        chuid.AddRange([
            0xD4, 0xE7, 0x39, 0xDA, 0x73, 0x9C, 0xED, 0x39, 0xCE, 0x73, 0x9D, 0x83, 0x68,
            0x58, 0x21, 0x08, 0x42, 0x10, 0x84, 0x21, 0xC8, 0x42, 0x10, 0xC3, 0xEB,
        ]);

        // 34 - GUID. This is what the minidriver keys the card on, so it is
        // random per card rather than derived from anything: two cards sharing
        // a GUID are one card as far as Windows is concerned.
        chuid.AddRange([0x34, 0x10]);
        chuid.AddRange(guid);

        // 35 - expiry, as eight ASCII digits rather than BCD.
        chuid.AddRange([0x35, 0x08]);
        chuid.AddRange(System.Text.Encoding.ASCII.GetBytes(
            expires.ToString("yyyyMMdd", System.Globalization.CultureInfo.InvariantCulture)));

        // 3E - issuer signature, deliberately empty. FE - LRC, which PIV
        // defines as always empty.
        chuid.AddRange([0x3E, 0x00, 0xFE, 0x00]);

        return [.. chuid];
    }

    /// <summary>
    /// Builds a CCC. The card identifier is fresh; the rest is fixed by the
    /// standard and says "one PIV application, no extras".
    /// </summary>
    public static byte[] BuildCapabilityContainer()
    {
        var identifier = new byte[14];
        RandomNumberGenerator.Fill(identifier);

        var ccc = new List<byte>();

        // F0 - card identifier. The prefix is the GSC-IS issuer identifier
        // that says "this is a PIV card"; the tail is per card.
        ccc.AddRange([0xF0, 0x15]);
        ccc.AddRange([0xA0, 0x00, 0x00, 0x01, 0x16, 0xFF, 0x02]);
        ccc.AddRange(identifier);

        ccc.AddRange([0xF1, 0x01, 0x21]); // container version 2.1
        ccc.AddRange([0xF2, 0x01, 0x21]); // grammar version 2.1
        ccc.AddRange([0xF3, 0x00]);       // applicationCardURL, none
        ccc.AddRange([0xF4, 0x01, 0x00]); // PKCS#15 not present
        ccc.AddRange([0xF5, 0x01, 0x10]); // data model number, PIV
        ccc.AddRange([0xF6, 0x00]);       // access control rule table
        ccc.AddRange([0xF7, 0x00]);       // card APDUs
        ccc.AddRange([0xFA, 0x00]);       // redirection tag
        ccc.AddRange([0xFB, 0x00]);       // capability tuples
        ccc.AddRange([0xFC, 0x00]);       // status tuples
        ccc.AddRange([0xFD, 0x00]);       // next CCC
        ccc.AddRange([0xFE, 0x00]);       // LRC

        return [.. ccc];
    }
}

/// <summary>
/// Which of the two identity objects had to be written. Both false is a card
/// that was already usable.
/// </summary>
public readonly record struct CardIdentityWritten(bool Chuid, bool CapabilityContainer)
{
    public bool Anything => Chuid || CapabilityContainer;

    public override string ToString() => (Chuid, CapabilityContainer) switch
    {
        (true, true) => "CHUID and CCC",
        (true, false) => "CHUID",
        (false, true) => "CCC",
        _ => "nothing",
    };
}
