using System.IO.Compression;
using System.Security.Cryptography.X509Certificates;

namespace Blinky.Piv;

/// <summary>
/// The read path: everything Blinky can learn about a token without writing a
/// single byte to it.
/// </summary>
/// <remarks>
/// Two rules run through all of it. Nothing is inferred from a model name or a
/// firmware number where the card can be asked instead. And where the card
/// cannot be asked - firmware below 5.3 has no GET METADATA - the answer is
/// <see cref="PinState.Unknown"/> rather than a guess, because an operator
/// needs to see the difference between "not set" and "cannot tell".
/// </remarks>
public sealed class PivSession(PivConnection connection)
{
    private const byte InsVerify = 0x20;
    private const byte InsGetData = 0xCB;
    private const byte InsGetMetadata = 0xF7;
    private const byte InsGetSerial = 0xF8;
    private const byte InsGetVersion = 0xFD;

    private const byte PinSlot = 0x80;
    private const byte PukSlot = 0x81;
    private const byte ManagementKeySlot = 0x9B;
    private const byte BiometricSlot = 0x96;

    // GET METADATA tags.
    private const byte TagAlgorithm = 0x01;
    private const byte TagPolicy = 0x02;
    private const byte TagOrigin = 0x03;
    private const byte TagPublicKey = 0x04;
    private const byte TagDefault = 0x05;
    private const byte TagRetries = 0x06;
    private const byte TagFingerprints = 0x07;
    private const byte TagTemporaryPin = 0x08;

    public PivConnection Connection { get; } = connection;

    /// <summary>Selects the PIV applet. False when the card has none.</summary>
    public bool Select() => Connection.SelectPiv();

    /// <summary>Firmware version, or <see cref="FirmwareVersion.Unknown"/>.</summary>
    public FirmwareVersion GetFirmwareVersion()
    {
        var response = Connection.Send(new ApduCommand(InsGetVersion, le: 0));

        return response.IsSuccess
            ? FirmwareVersion.Parse(response.Data)
            : FirmwareVersion.Unknown;
    }

    /// <summary>The token's serial number, or null on firmware that will not say.</summary>
    public uint? GetSerialNumber()
    {
        var response = Connection.Send(new ApduCommand(InsGetSerial, le: 0));

        if (!response.IsSuccess || response.Data.Length != 4)
        {
            return null;
        }

        var d = response.Data;
        return (uint)((d[0] << 24) | (d[1] << 16) | (d[2] << 8) | d[3]);
    }

    /// <summary>
    /// The PIN's state and remaining attempts. Sends VERIFY with no data, which
    /// reports the counter without consuming an attempt - the only read-only
    /// way to ask - and combines it with metadata where the firmware has it.
    /// </summary>
    public PinMetadata GetPinMetadata() => ReadCredential(PinSlot, isPuk: false);

    /// <summary>The PUK's state. Reports <see cref="PinState.NotConfigured"/>
    /// when the token has no PUK at all.</summary>
    public PinMetadata GetPukMetadata() => ReadCredential(PukSlot, isPuk: true);

    private PinMetadata ReadCredential(byte slot, bool isPuk)
    {
        int? remainingFromProbe = null;
        var blocked = false;

        // The PUK has no VERIFY of its own; only the PIN can be probed this way.
        if (!isPuk)
        {
            var probe = Connection.Send(new ApduCommand(InsVerify, p2: slot));
            remainingFromProbe = probe.Status.RetriesLeft;
            blocked = probe.Status.Value == StatusWord.AuthenticationMethodBlocked;
        }

        var metadata = TryGetMetadata(slot);
        if (metadata is null)
        {
            // Firmware below 5.3. The probe is all there is.
            var state = blocked ? PinState.Blocked
                : remainingFromProbe is null ? PinState.Unknown
                : PinState.Set;

            return new PinMetadata(state, null, remainingFromProbe);
        }

        int? total = null;
        int? remaining = null;
        if (metadata.TryGetValue(TagRetries, out var retries))
        {
            if (retries.Length >= 2)
            {
                total = retries[0];
                remaining = retries[1];
            }
            else if (retries.Length == 1)
            {
                remaining = retries[0];
            }
        }

        remaining ??= remainingFromProbe;

        // Total retries of zero is not "no attempts left" - it means there is
        // no such credential on the token. Firmware 5.7 can delete the PUK, and
        // a Bio Multi-protocol ships with it deleted.
        if (isPuk && total == 0)
        {
            return new PinMetadata(PinState.NotConfigured, 0, 0);
        }

        var isDefault = metadata.TryGetValue(TagDefault, out var flag)
                        && flag.Length > 0 && flag[0] == 1;

        var resolved = blocked || remaining == 0 && total > 0 ? PinState.Blocked
            : isDefault ? PinState.Default
            : PinState.Set;

        return new PinMetadata(resolved, total, remaining);
    }

    /// <summary>
    /// The management key's algorithm and whether it is still the factory one.
    /// Null on firmware that cannot be asked, which is recorded as unknown
    /// rather than assumed - both 3DES and AES-192 tokens exist in the field.
    /// </summary>
    public ManagementKeyMetadata? GetManagementKeyMetadata()
    {
        var metadata = TryGetMetadata(ManagementKeySlot);
        if (metadata is null)
        {
            return null;
        }

        var algorithm = metadata.TryGetValue(TagAlgorithm, out var alg) && alg.Length > 0
            ? (PivAlgorithm)alg[0]
            : PivAlgorithm.Unknown;

        var isDefault = metadata.TryGetValue(TagDefault, out var flag)
                        && flag.Length > 0 && flag[0] == 1;

        var touch = metadata.TryGetValue(TagPolicy, out var policy) && policy.Length == 2
            ? (TouchPolicy)policy[1]
            : TouchPolicy.Unknown;

        return new ManagementKeyMetadata(algorithm, isDefault, touch);
    }

    /// <summary>
    /// Biometric state, or null when the token does not do on-card comparison.
    /// The detection is the card's answer to slot 96, never the model name.
    /// </summary>
    public BiometricMetadata? GetBiometricMetadata()
    {
        var metadata = TryGetMetadata(BiometricSlot);
        if (metadata is null)
        {
            return null;
        }

        var enrolled = metadata.TryGetValue(TagFingerprints, out var f)
                       && f.Length > 0 && f[0] == 1;

        // Here tag 06 carries one byte, not the two the PIN slot uses.
        int? attempts = metadata.TryGetValue(TagRetries, out var r) && r.Length > 0
            ? r[^1]
            : null;

        var temporaryPin = metadata.TryGetValue(TagTemporaryPin, out var t)
                           && t.Length > 0 && t[0] == 1;

        return new BiometricMetadata(enrolled, attempts, temporaryPin);
    }

    /// <summary>What the card says about a key slot, or null when it holds no key.</summary>
    public SlotMetadata? GetSlotMetadata(PivSlot slot)
    {
        var metadata = TryGetMetadata(slot.Id);
        if (metadata is null)
        {
            return null;
        }

        var algorithm = metadata.TryGetValue(TagAlgorithm, out var alg) && alg.Length > 0
            ? (PivAlgorithm)alg[0]
            : PivAlgorithm.Unknown;

        var pin = PinPolicy.Unknown;
        var touch = TouchPolicy.Unknown;
        if (metadata.TryGetValue(TagPolicy, out var policy) && policy.Length == 2)
        {
            pin = (PinPolicy)policy[0];
            touch = (TouchPolicy)policy[1];
        }

        var origin = metadata.TryGetValue(TagOrigin, out var o) && o.Length > 0
            ? (KeyOrigin)o[0]
            : KeyOrigin.Unknown;

        metadata.TryGetValue(TagPublicKey, out var publicKey);

        return new SlotMetadata(slot, algorithm, pin, touch, origin, publicKey);
    }

    /// <summary>
    /// The DER of the certificate in a slot, or null when the slot has none.
    /// An empty slot is a normal finding during inventory, not an error.
    /// </summary>
    public byte[]? GetCertificate(PivSlot slot)
    {
        var tag = slot.CertificateObject
                  ?? throw new ArgumentException($"Slot {slot} holds no certificate object.",
                      nameof(slot));

        var data = ReadDataObject(tag, $"GET DATA {slot}");

        return data is null ? null : ExtractCertificate(data);
    }

    /// <summary>Reads a certificate and parses it, or null when the slot is empty.</summary>
    public X509Certificate2? GetCertificateAsX509(PivSlot slot)
    {
        var der = GetCertificate(slot);
        if (der is null)
        {
            return null;
        }

        try
        {
            return X509CertificateLoader.LoadCertificate(der);
        }
        catch (Exception ex)
        {
            throw new PivProtocolException(
                $"Slot {slot} holds {der.Length} bytes that are not an X.509 certificate: "
                + ex.Message);
        }
    }

    /// <summary>
    /// Asks the token to attest to the key in a slot. Returns null when the
    /// slot holds no key, which is what a blank token answers.
    /// </summary>
    public X509Certificate2? Attest(PivSlot slot)
    {
        const byte insAttest = 0xF9;

        var response = Connection.Send(new ApduCommand(insAttest, p1: slot.Id, le: 0));

        if (response.Status.Value is StatusWord.IncorrectParameters
            or StatusWord.ReferencedDataNotFound)
        {
            return null;
        }

        PivStatus.ThrowIfFailed(response.Status, $"ATTEST {slot}");

        try
        {
            return X509CertificateLoader.LoadCertificate(response.Data);
        }
        catch (Exception ex)
        {
            throw new PivProtocolException(
                $"ATTEST {slot} returned {response.Data.Length} bytes that are not a "
                + $"certificate: {ex.Message}");
        }
    }

    /// <summary>
    /// The token's own attestation certificate, from slot F9. This is the
    /// intermediate every attestation from this device chains through, and it
    /// differs from one device to the next - so it is read, never pinned.
    /// </summary>
    public X509Certificate2? GetAttestationCertificate()
    {
        var der = ReadDataObject([0x5F, 0xFF, 0x01], "GET DATA F9");
        if (der is null)
        {
            return null;
        }

        var certificate = ExtractCertificate(der) ?? der;

        try
        {
            return X509CertificateLoader.LoadCertificate(certificate);
        }
        catch (Exception ex)
        {
            throw new PivProtocolException(
                $"Slot F9 holds bytes that are not a certificate: {ex.Message}");
        }
    }

    /// <summary>
    /// One read-only pass over the token: identity, credential state,
    /// biometrics, and every credential slot.
    /// </summary>
    public TokenInventory ReadInventory(bool includeCertificates = true)
    {
        var firmware = GetFirmwareVersion();
        var serial = GetSerialNumber();
        var pin = GetPinMetadata();
        var puk = GetPukMetadata();
        var managementKey = GetManagementKeyMetadata();
        var biometrics = GetBiometricMetadata();

        var slots = new List<SlotInventory>();
        foreach (var slot in PivSlot.Credentials)
        {
            var certificate = includeCertificates ? GetCertificate(slot) : null;
            var metadata = GetSlotMetadata(slot);

            slots.Add(new SlotInventory(slot, certificate is not null, metadata, certificate));
        }

        return new TokenInventory(serial, firmware, pin, puk, managementKey, biometrics, slots);
    }

    /// <summary>Reads a data object, or null when the card holds none.</summary>
    private byte[]? ReadDataObject(byte[] tag, string operation)
    {
        byte[] request = [0x5C, (byte)tag.Length, .. tag];
        var response = Connection.Send(
            new ApduCommand(InsGetData, p1: 0x3F, p2: 0xFF, data: request, le: 0));

        if (response.Status.IsEmptySlot)
        {
            return null;
        }

        PivStatus.ThrowIfFailed(response.Status, operation);

        return response.Data;
    }

    /// <summary>
    /// Sends GET METADATA for a slot. Null covers both "this firmware has no
    /// such command" (6D00) and "nothing in that slot" (6A80, 6A88) - neither
    /// is an error, and both mean the same thing to a caller: no answer.
    /// </summary>
    private Dictionary<byte, byte[]>? TryGetMetadata(byte slot)
    {
        var response = Connection.Send(new ApduCommand(InsGetMetadata, p2: slot, le: 0));

        if (!response.IsSuccess)
        {
            return response.Status.Value is StatusWord.InstructionNotSupported
                   or StatusWord.IncorrectParameters
                   or StatusWord.FileNotFound
                   or StatusWord.ReferencedDataNotFound
                ? null
                : throw PivStatus.ToException(response.Status, $"GET METADATA {slot:X2}");
        }

        return Tlv.ParseSimple(response.Data);
    }

    /// <summary>
    /// Pulls the certificate out of a PIV data object: tag 70 is the DER, and
    /// bit 0 of tag 71 says it arrived gzipped.
    /// </summary>
    internal static byte[]? ExtractCertificate(byte[] dataObject)
    {
        var outer = Tlv.ParseBer(dataObject);
        var body = outer.TryGetValue(0x53, out var wrapped) ? wrapped : dataObject;

        var inner = Tlv.ParseBer(body);
        if (!inner.TryGetValue(0x70, out var der) || der.Length == 0)
        {
            return null;
        }

        if (inner.TryGetValue(0x71, out var info) && info.Length > 0 && (info[0] & 0x01) != 0)
        {
            using var input = new MemoryStream(der);
            using var gzip = new GZipStream(input, CompressionMode.Decompress);
            using var output = new MemoryStream();
            gzip.CopyTo(output);
            der = output.ToArray();
        }

        return der;
    }
}
