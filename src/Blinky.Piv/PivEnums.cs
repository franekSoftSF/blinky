namespace Blinky.Piv;

/// <summary>Key algorithms the PIV applet knows, by their on-card identifier.</summary>
public enum PivAlgorithm : byte
{
    Unknown = 0x00,
    Rsa3072 = 0x05,
    Rsa1024 = 0x06,
    Rsa2048 = 0x07,
    TripleDes = 0x03,
    Aes128 = 0x08,
    Aes192 = 0x0A,
    Aes256 = 0x0C,
    EccP256 = 0x11,
    EccP384 = 0x14,
    Rsa4096 = 0x16,
    Ed25519 = 0xE0,
    X25519 = 0xE1,

    /// <summary>Not a key: what metadata reports for the PIN and PUK slots.</summary>
    PinPuk = 0xFF,
}

/// <summary>How often the PIN must be presented before the key will be used.</summary>
public enum PinPolicy : byte
{
    Unknown = 0x00,
    Never = 0x01,
    Once = 0x02,
    Always = 0x03,

    /// <summary>
    /// A fingerprint match, once per session.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Bio Multi-protocol only, and the difference is not cosmetic: a key
    /// generated with <see cref="Once"/> wants a <b>PIN</b>, and a successful
    /// fingerprint match does not satisfy it. Observed on firmware 5.7.2 —
    /// <c>VERIFY 96</c> answered <c>9000</c>, the user was verified, and the
    /// slot then refused to sign with <c>6982</c>, its PIN policy unsatisfied.
    /// </para>
    /// <para>
    /// So biometric enrolment is decided at <b>generation</b>, not at
    /// verification. A token whose owner will use a finger has to be given a
    /// key that says so, and it cannot be changed afterwards without replacing
    /// the key.
    /// </para>
    /// </remarks>
    MatchOnce = 0x04,

    /// <summary>A fingerprint match before every single operation.</summary>
    MatchAlways = 0x05,
}

/// <summary>Whether the token demands a finger on the contact.</summary>
public enum TouchPolicy : byte
{
    Unknown = 0x00,
    Never = 0x01,
    Always = 0x02,

    /// <summary>One touch counts for the next fifteen seconds.</summary>
    Cached = 0x03,
}

/// <summary>Whether the key was generated on the token or imported into it.</summary>
public enum KeyOrigin : byte
{
    Unknown = 0x00,
    Generated = 0x01,
    Imported = 0x02,
}

/// <summary>What can be said about a PIN or PUK without trying it.</summary>
public enum PinState
{
    /// <summary>Firmware too old to be asked, and no attempt made.</summary>
    Unknown,
    Default,
    Set,
    Blocked,

    /// <summary>
    /// No PUK at all. Firmware 5.7 can delete it, and a Bio Multi-protocol
    /// token ships that way - see docs/02-data-model.md.
    /// </summary>
    NotConfigured,
}
