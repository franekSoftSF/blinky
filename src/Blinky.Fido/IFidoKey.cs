namespace Blinky.Fido;

/// <summary>
/// A FIDO2 authenticator as the provisioning engine needs it, and no more.
/// </summary>
/// <remarks>
/// <para>
/// An interface rather than Yubico's <c>Fido2Session</c> directly, for the reason
/// KeyEnroll has a software authenticator in its tests: the order of the steps is
/// where the bugs are - a forced PIN change set before the ceremony, a PIN
/// generated that the key's complexity policy refuses - and that order is worth
/// testing on every build, not only on the day somebody has a key on the bench.
/// </para>
/// <para>
/// HID, not PC/SC. Nothing in <c>Blinky.Piv</c> is used below this line, and the
/// FIDO2 PIN here is a different PIN with a different retry counter from the PIV
/// one; nothing in this namespace may ever call it just "the PIN".
/// </para>
/// </remarks>
public interface IFidoKey : IDisposable
{
    /// <summary>Read afresh: a reset or a PIN change makes the previous answer wrong.</summary>
    FidoKeyInfo Info();

    /// <summary>The FIDO2 PIN's retry counter. Null when the key will not say.</summary>
    int? PinRetries();

    void SetPin(string pin);

    void ChangePin(string current, string next);

    /// <summary>Proves the PIN and keeps a token for what follows. Throws <see cref="FidoException"/>.</summary>
    void VerifyPin(string pin);

    void SetMinPinLength(int length);

    /// <summary>The next use of the key must change the PIN first.</summary>
    void ForceChangePin();

    /// <summary>Destroys every FIDO credential on the key. Accepted only shortly after power-up.</summary>
    void Reset();

    /// <param name="pin">Already verified; the key needs a token scoped to this rpId.</param>
    FidoMadeCredential MakeCredential(FidoCredentialRequest request, string pin, Action touch);
}

/// <param name="Serial">Null for a key that is not a YubiKey or will not say.</param>
/// <param name="SupportsConfig"><c>authnrCfg</c>: the key takes authenticatorConfig at all.</param>
/// <param name="SupportsMinPinLength"><c>setMinPINLength</c>, which is also what forceChangePin rides on.</param>
public sealed record FidoKeyInfo(
    long? Serial,
    string? Firmware,
    Guid Aaguid,
    IReadOnlyList<string> Versions,
    bool SupportsPin,
    bool PinSet,
    int MinPinLength,
    bool ForcePinChange,
    bool SupportsConfig,
    bool SupportsMinPinLength,
    int? RemainingDiscoverableCredentials)
{
    public bool CanForcePinChange => SupportsConfig && SupportsMinPinLength;
}

/// <summary>What <c>authenticatorMakeCredential</c> is asked, already reduced to CTAP terms.</summary>
public sealed record FidoCredentialRequest(
    byte[] ClientDataHash,
    string RpId,
    string RpName,
    byte[] UserId,
    string UserName,
    string UserDisplayName,
    IReadOnlyList<int> Algorithms,
    IReadOnlyList<byte[]> Exclude,
    bool ResidentKey,
    bool UserVerification,
    bool HmacSecret,
    string? CredProtect,
    bool EnforceCredProtect);

/// <param name="AttestationObject">WebAuthn's form: fmt, authData and attStmt under text keys.</param>
public sealed record FidoMadeCredential(byte[] CredentialId, byte[] AttestationObject);

/// <summary>The CTAP errors the engine reacts to; anything else is <see cref="Other"/>.</summary>
public enum FidoError
{
    Other,
    PinInvalid,
    PinBlocked,
    PinAuthBlocked,
    PinPolicyViolation,
    PinNotSet,
    CredentialExcluded,
    NotAllowed,
    OperationDenied,
    ActionTimeout,
    KeyStoreFull,
    Unsupported,
}

public sealed class FidoException(FidoError error, string message, Exception? inner = null)
    : Exception(message, inner)
{
    public FidoError Error { get; } = error;
}
