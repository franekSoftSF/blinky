using System.Formats.Asn1;
using System.Globalization;
using System.Security.Cryptography.X509Certificates;

namespace Blinky.Piv.Attestation;

/// <summary>
/// What a token says about a key it generated: which slot, which policies,
/// which firmware, and which device.
/// </summary>
/// <remarks>
/// None of this is trustworthy until the certificate it came from has been
/// chained to a pinned Yubico root - see <see cref="AttestationVerifier"/>.
/// The type deliberately does not carry a "valid" flag, so that a caller
/// cannot read the fields and forget to check.
/// </remarks>
public sealed record YubicoAttestation(
    X509Certificate2 Certificate,
    FirmwareVersion Firmware,
    uint? SerialNumber,
    PinPolicy PinPolicy,
    TouchPolicy TouchPolicy,
    FormFactor FormFactor,
    bool IsFipsDevice,
    PivSlot? Slot)
{
    // Read off a real 5.7.1, because the numbers are neither guessable nor
    // sequential: 3, then 7, 8, 9. Do not tidy them.
    internal const string FirmwareOid = "1.3.6.1.4.1.41482.3.3";
    internal const string SerialOid = "1.3.6.1.4.1.41482.3.7";
    internal const string PolicyOid = "1.3.6.1.4.1.41482.3.8";
    internal const string FormFactorOid = "1.3.6.1.4.1.41482.3.9";

    /// <summary>The DER of the attested key's SubjectPublicKeyInfo.</summary>
    public byte[] PublicKeyInfo => Certificate.PublicKey.ExportSubjectPublicKeyInfo();

    /// <summary>
    /// Reads the Yubico extensions off an attestation certificate. Missing
    /// extensions come back as unknown rather than throwing: an older firmware
    /// legitimately omits some, and the verifier is what decides whether the
    /// gaps matter.
    /// </summary>
    public static YubicoAttestation Parse(X509Certificate2 certificate)
    {
        var firmware = FirmwareVersion.Unknown;
        uint? serial = null;
        var pinPolicy = PinPolicy.Unknown;
        var touchPolicy = TouchPolicy.Unknown;
        var formFactor = FormFactor.Unknown;
        var fips = false;

        foreach (var extension in certificate.Extensions)
        {
            var raw = extension.RawData;

            switch (extension.Oid?.Value)
            {
                case FirmwareOid when raw.Length == 3:
                    firmware = new FirmwareVersion(raw[0], raw[1], raw[2]);
                    break;

                case SerialOid:
                    serial = ReadSerial(raw);
                    break;

                case PolicyOid when raw.Length == 2:
                    pinPolicy = (PinPolicy)raw[0];
                    touchPolicy = (TouchPolicy)raw[1];
                    break;

                case FormFactorOid when raw.Length == 1:
                    // The high bit marks a FIPS device; the rest is the shape.
                    fips = (raw[0] & 0x80) != 0;
                    formFactor = (FormFactor)(raw[0] & 0x7F);
                    break;
            }
        }

        return new YubicoAttestation(certificate, firmware, serial, pinPolicy, touchPolicy,
            formFactor, fips, ReadSlot(certificate));
    }

    /// <summary>
    /// The slot is in the subject, as "YubiKey PIV Attestation 9a". Null when
    /// it cannot be read, which the verifier treats as a failure rather than a
    /// detail - a caller asking about 9A must not be handed 9E's attestation.
    /// </summary>
    private static PivSlot? ReadSlot(X509Certificate2 certificate)
    {
        var subject = certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
        if (string.IsNullOrEmpty(subject))
        {
            return null;
        }

        var candidate = subject[^2..];
        return byte.TryParse(candidate, NumberStyles.HexNumber, CultureInfo.InvariantCulture,
            out var id)
            ? new PivSlot(id, candidate.ToUpperInvariant())
            : null;
    }

    private static uint? ReadSerial(byte[] raw)
    {
        try
        {
            var value = new AsnReader(raw, AsnEncodingRules.DER).ReadInteger();
            return value >= 0 && value <= uint.MaxValue ? (uint)value : null;
        }
        catch (AsnContentException)
        {
            return null;
        }
    }
}
