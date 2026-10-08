using System.Buffers.Text;
using System.Text.Json;

namespace Blinky.Passkeys;

/// <summary>Binary values as providers actually send them.</summary>
internal static class WireBinary
{
    /// <summary>
    /// Base64, base64url, padded or not, or an array of byte values - signed ones
    /// included, which is how a Java <c>byte[]</c> or a JavaScript
    /// <c>Int8Array</c> serialises. KeyEnroll met all of these across four
    /// providers; accepting them in one place keeps the providers honest about
    /// which they send without each one guessing.
    /// </summary>
    public static byte[] Read(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.String => Decode(value.GetString()!),
        JsonValueKind.Array => value.EnumerateArray().Select(b => (byte)(b.GetInt32() & 0xFF)).ToArray(),
        _ => throw new PasskeyDirectoryException(
            $"Expected a binary value, got JSON {value.ValueKind}."),
    };

    public static byte[] Decode(string text)
    {
        var url = text.Trim().Replace('+', '-').Replace('/', '_').TrimEnd('=');

        try
        {
            return Base64Url.DecodeFromChars(url);
        }
        catch (FormatException e)
        {
            throw new PasskeyDirectoryException("A binary value is not base64 in any spelling.", null, e);
        }
    }

    public static bool TryDecode(string text, out byte[] bytes)
    {
        var url = text.Trim().TrimEnd('=');

        if (url.Length % 4 == 1 || url.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '-' or '_')))
        {
            bytes = [];
            return false;
        }

        try
        {
            bytes = Base64Url.DecodeFromChars(url);
            return true;
        }
        catch (FormatException)
        {
            bytes = [];
            return false;
        }
    }

    public static string Encode(ReadOnlySpan<byte> bytes) => Base64Url.EncodeToString(bytes);
}
