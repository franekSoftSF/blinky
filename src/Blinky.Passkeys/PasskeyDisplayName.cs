namespace Blinky.Passkeys;

/// <summary>The name a key is registered under.</summary>
public static class PasskeyDisplayName
{
    /// <summary>
    /// Appends the serial number, shortening the base rather than the serial when
    /// the provider limits the length. Entra refuses more than thirty characters,
    /// and "YubiKey 5C NFC" plus an eight-digit serial already comes close; a
    /// truncation that cut the serial would leave a helpdesk unable to tell which
    /// of a user's keys was lost.
    /// </summary>
    public static string Compose(string baseName, long? serial, int? limit)
    {
        var name = baseName.Trim();

        if (serial is not > 0)
        {
            return limit is { } max && name.Length > max ? name[..max] : name;
        }

        var suffix = serial.Value.ToString(System.Globalization.CultureInfo.InvariantCulture);

        if (name.Length == 0)
        {
            name = "YubiKey";
        }

        if (limit is { } room)
        {
            name = name[..Math.Min(name.Length, Math.Max(0, room - suffix.Length - 1))].TrimEnd();
        }

        return $"{name} {suffix}".Trim();
    }
}
