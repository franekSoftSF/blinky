namespace Blinky.Pki.BuiltIn;

/// <summary>
/// How a CA holds its private key.
/// </summary>
/// <remarks>
/// <para>
/// Named in the model before there is more than one of them, so that the shape
/// the console reads does not change when SoftHSM and a real device arrive.
/// See docs/04-pki-backends.md.
/// </para>
/// <para>
/// The distinction that matters is not "software or hardware" — SoftHSM keeps
/// its keys in files too, encrypted with a PIN the process has to hold. It is
/// whether the key leaves the store: a tier that hands out a signature is a
/// different thing from one that hands out a key, and only the first is worth
/// the word custody.
/// </para>
/// </remarks>
public enum KeyCustodyTier
{
    /// <summary>Nothing said. A backend that does not report one.</summary>
    Unknown,

    /// <summary>An encrypted PKCS#12 on a volume, and the password beside it.</summary>
    File,

    /// <summary>SoftHSM over PKCS#11: the interface of a device, on a disk.</summary>
    SoftHsm,

    /// <summary>A PKCS#11 device that will not export the key at all.</summary>
    Hsm,
}

/// <summary>
/// What to tell an operator about where the signing key lives.
/// </summary>
/// <param name="ProductionReady">
/// Whether this arrangement is one to run a real deployment on. False is not a
/// fault — it means the configuration is a laboratory one and says so, which is
/// better than a console that looks the same either way.
/// </param>
/// <param name="Detail">
/// A sentence for a person. Says what the tier means rather than repeating its
/// name.
/// </param>
public sealed record KeyCustody(
    KeyCustodyTier Tier,
    string Description,
    bool ProductionReady,
    string Detail)
{
    /// <summary>An encrypted file, which is where every lab starts.</summary>
    public static KeyCustody OfFile(string path) => new(
        KeyCustodyTier.File,
        $"file: {path}",
        ProductionReady: false,
        "The signing key is a PKCS#12 on this machine, and the password that opens it is in "
        + "the same deployment. Anybody who can read both can sign as this CA. Correct for a "
        + "laboratory, and the thing to change first before it is not one.");

    /// <summary>A backend that keeps its own key and does not say how.</summary>
    public static KeyCustody External(string what) => new(
        KeyCustodyTier.Unknown,
        what,
        ProductionReady: true,
        "The key belongs to a certificate authority this deployment does not run, so its "
        + "custody is that authority's arrangement rather than one Blinky can report on.");
}
