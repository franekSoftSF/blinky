using System.Globalization;

namespace Blinky.Piv;

/// <summary>
/// The token's firmware version, which decides what it can be asked.
/// </summary>
/// <remarks>
/// Two thresholds matter and both were confirmed on hardware: 5.3 brings
/// GET METADATA, so before it the card cannot be asked about its own state at
/// all; 5.7 changes the default management key from 3DES to AES-192 and adds
/// larger RSA and the Edwards curves.
/// </remarks>
public readonly record struct FirmwareVersion(byte Major, byte Minor, byte Patch)
    : IComparable<FirmwareVersion>
{
    public static readonly FirmwareVersion Unknown = default;

    /// <summary>Firmware 5.3 and later can be asked about its own state.</summary>
    public bool SupportsMetadata => this >= new FirmwareVersion(5, 3, 0);

    /// <summary>Firmware 5.7 and later ships an AES-192 management key.</summary>
    public bool DefaultsToAesManagementKey => this >= new FirmwareVersion(5, 7, 0);

    public static FirmwareVersion Parse(ReadOnlySpan<byte> response) => response.Length == 3
        ? new FirmwareVersion(response[0], response[1], response[2])
        : throw new PivProtocolException(
            $"GET VERSION returned {response.Length} bytes, expected 3.");

    public int CompareTo(FirmwareVersion other)
    {
        var major = Major.CompareTo(other.Major);
        if (major != 0)
        {
            return major;
        }

        var minor = Minor.CompareTo(other.Minor);
        return minor != 0 ? minor : Patch.CompareTo(other.Patch);
    }

    public static bool operator <(FirmwareVersion a, FirmwareVersion b) => a.CompareTo(b) < 0;

    public static bool operator >(FirmwareVersion a, FirmwareVersion b) => a.CompareTo(b) > 0;

    public static bool operator <=(FirmwareVersion a, FirmwareVersion b) => a.CompareTo(b) <= 0;

    public static bool operator >=(FirmwareVersion a, FirmwareVersion b) => a.CompareTo(b) >= 0;

    public override string ToString() =>
        string.Create(CultureInfo.InvariantCulture, $"{Major}.{Minor}.{Patch}");
}
