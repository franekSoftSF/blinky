using System.Buffers.Binary;
using System.Globalization;
using System.Text;

namespace Blinky.Directory;

/// <summary>
/// Turns the directory's <c>objectSid</c> into the form everything else uses.
/// </summary>
/// <remarks>
/// <para>
/// LDAP hands the attribute over as bytes; certificates, the database and every
/// person who has to read one want <c>S-1-5-21-…</c>. Written here rather than
/// taken from <c>System.Security.Principal.SecurityIdentifier</c> because that
/// type is Windows-only, and this runs in a Linux container.
/// </para>
/// <para>
/// The layout, from MS-DTYP:
/// </para>
/// <code>
///   byte      0  revision, always 1
///   byte      1  how many sub-authorities follow
///   bytes   2-7  identifier authority, big-endian
///   then         one 32-bit sub-authority each, little-endian
/// </code>
/// <para>
/// Two endiannesses in one structure, which is the entire reason this is worth
/// a file and a test rather than four lines inline.
/// </para>
/// </remarks>
public static class SecurityIdentifier
{
    /// <summary>
    /// Formats a binary <c>objectSid</c>.
    /// </summary>
    /// <returns>Null when the bytes are not a SID, rather than a plausible lie.</returns>
    public static string? Format(ReadOnlySpan<byte> sid)
    {
        // Revision, count, and the six-byte authority: anything shorter cannot
        // be one.
        if (sid.Length < 8 || sid[0] != 1)
        {
            return null;
        }

        int subAuthorities = sid[1];

        if (sid.Length != 8 + (subAuthorities * 4))
        {
            // A truncated SID would otherwise format as a shorter one that
            // belongs to somebody else.
            return null;
        }

        // Six bytes, big-endian, and no primitive is that wide - so it is read
        // a byte at a time rather than through a cast that would silently take
        // four of them.
        ulong authority = 0;
        for (var i = 2; i < 8; i++)
        {
            authority = (authority << 8) | sid[i];
        }

        var text = new StringBuilder("S-1-");
        text.Append(authority.ToString(CultureInfo.InvariantCulture));

        for (var i = 0; i < subAuthorities; i++)
        {
            var value = BinaryPrimitives.ReadUInt32LittleEndian(sid.Slice(8 + (i * 4), 4));

            text.Append('-');
            text.Append(value.ToString(CultureInfo.InvariantCulture));
        }

        return text.ToString();
    }

    /// <summary>
    /// Whether a string looks like a SID this project would accept.
    /// </summary>
    /// <remarks>
    /// For the boundary, where an operator can type one. It does not prove the
    /// SID exists — nothing but the directory can — but it catches the typed
    /// value that would otherwise be stored and fail three weeks later at a
    /// logon, which is the worst moment to discover it.
    /// </remarks>
    public static bool LooksValid(string? sid)
    {
        if (string.IsNullOrWhiteSpace(sid))
        {
            return false;
        }

        var parts = sid.Split('-');

        // S, revision, authority, and at least one sub-authority.
        if (parts.Length < 4 || parts[0] is not ("S" or "s"))
        {
            return false;
        }

        if (parts[1] != "1")
        {
            return false;
        }

        foreach (var part in parts.AsSpan(2))
        {
            if (!ulong.TryParse(part, NumberStyles.None, CultureInfo.InvariantCulture, out _))
            {
                return false;
            }
        }

        return true;
    }
}
