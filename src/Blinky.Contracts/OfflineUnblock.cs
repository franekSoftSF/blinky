using System.Security.Cryptography;
using System.Text;

namespace Blinky.Contracts;

/// <summary>
/// The codes a person reads down a telephone.
/// </summary>
/// <remarks>
/// <para>
/// Crockford's base32 alphabet: no <c>I</c>, <c>L</c>, <c>O</c> or <c>U</c>, so
/// there is no pair a person can confuse by ear or by eye, and no accidental
/// word. Decoding folds <c>I</c> and <c>L</c> onto <c>1</c> and <c>O</c> onto
/// <c>0</c>, because somebody will type what they think they heard.
/// </para>
/// <para>
/// Every code carries a check character. That is the whole reason these are not
/// eight bare digits: a PIN unblock has three PUK attempts behind it, and a
/// mistyped code that reaches the card spends one of them. Caught here it costs
/// a "read that back to me" instead.
/// </para>
/// </remarks>
public static class TransferCode
{
    private const string Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    /// <summary>Encodes bytes and appends a check character.</summary>
    public static string Encode(ReadOnlySpan<byte> data)
    {
        var builder = new StringBuilder();

        var buffer = 0;
        var bits = 0;

        foreach (var b in data)
        {
            buffer = (buffer << 8) | b;
            bits += 8;

            while (bits >= 5)
            {
                builder.Append(Alphabet[(buffer >> (bits - 5)) & 31]);
                bits -= 5;
            }
        }

        if (bits > 0)
        {
            builder.Append(Alphabet[(buffer << (5 - bits)) & 31]);
        }

        var body = builder.ToString();

        return Group(body + Check(body));
    }

    /// <summary>
    /// Decodes a code somebody typed. Null when the check character disagrees,
    /// which is a transcription error and not an attack.
    /// </summary>
    public static byte[]? Decode(string? code)
    {
        if (string.IsNullOrWhiteSpace(code))
        {
            return null;
        }

        var cleaned = new StringBuilder();

        foreach (var c in code.ToUpperInvariant())
        {
            var normalised = c switch
            {
                'I' or 'L' => '1',
                'O' => '0',
                '-' or ' ' => '\0',
                _ => c,
            };

            if (normalised == '\0')
            {
                continue;
            }

            if (!Alphabet.Contains(normalised, StringComparison.Ordinal))
            {
                return null;
            }

            cleaned.Append(normalised);
        }

        if (cleaned.Length < 2)
        {
            return null;
        }

        var body = cleaned.ToString(0, cleaned.Length - 1);
        var check = cleaned[^1];

        // Fixed-time so that a wrong code cannot be walked character by
        // character. The stakes are small here and the habit is cheap.
        if (!CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(check.ToString()),
                Encoding.ASCII.GetBytes(Check(body).ToString())))
        {
            return null;
        }

        var bytes = new List<byte>();
        var buffer = 0;
        var bits = 0;

        foreach (var c in body)
        {
            buffer = (buffer << 5) | Alphabet.IndexOf(c, StringComparison.Ordinal);
            bits += 5;

            if (bits >= 8)
            {
                bytes.Add((byte)((buffer >> (bits - 8)) & 0xFF));
                bits -= 8;
            }
        }

        return [.. bytes];
    }

    /// <summary>Groups in fours, which is how people read numbers aloud.</summary>
    private static string Group(string code) =>
        string.Join('-', Enumerable.Range(0, (code.Length + 3) / 4)
            .Select(i => code.Substring(i * 4, Math.Min(4, code.Length - (i * 4)))));

    private static char Check(string body)
    {
        var sum = 0;

        // Position-weighted, so two characters swapped in transcription - the
        // most common mistake after a single wrong letter - does not produce
        // the same check.
        for (var i = 0; i < body.Length; i++)
        {
            sum += (i + 1) * Alphabet.IndexOf(body[i], StringComparison.Ordinal);
        }

        return Alphabet[sum % 32];
    }
}

/// <summary>
/// Unblocking a token on a machine that cannot reach the backend.
/// </summary>
/// <remarks>
/// <para>
/// The workstation is offline; the person answering the telephone is not. The
/// agent shows a challenge, somebody reads it out, an operator types it into
/// the console, and reads back the response.
/// </para>
/// <para>
/// The response carries the PUK, and there is no way around that: the card
/// needs the PUK bytes and an offline machine has no other way to learn them.
/// The alternative — a derivation secret on every workstation — trades a value
/// spoken once for a value that lets any compromised laptop unblock any token
/// on its own. That is the worse trade, and it is why this design accepts the
/// spoken value and makes it worthless instead of trying to hide it.
/// </para>
/// <para>
/// Worthless because it is spent: the moment it is used, both sides derive the
/// replacement with <see cref="PukDerivation"/> — independently, with no
/// network between them — and the code that was read aloud opens nothing.
/// </para>
/// </remarks>
public static class OfflineUnblock
{
    /// <summary>How many random bytes bind a challenge to one occasion.</summary>
    public const int NonceLength = 5;

    /// <summary>Builds the code the agent shows.</summary>
    public static string Challenge(long serial, ReadOnlySpan<byte> nonce)
    {
        Span<byte> payload = stackalloc byte[4 + NonceLength];

        // Four bytes of serial: YubiKey serials are 32-bit, and the operator
        // has to be able to see which token this is about.
        BitConverter.TryWriteBytes(payload, (uint)serial);
        nonce[..NonceLength].CopyTo(payload[4..]);

        return TransferCode.Encode(payload);
    }

    /// <summary>Reads a challenge back. Null when it is not one.</summary>
    public static (long Serial, byte[] Nonce)? ReadChallenge(string? code)
    {
        var payload = TransferCode.Decode(code);

        if (payload is null || payload.Length < 4 + NonceLength)
        {
            return null;
        }

        return (BitConverter.ToUInt32(payload, 0), payload[4..(4 + NonceLength)]);
    }

    /// <summary>Wraps a PUK as the code an operator reads back.</summary>
    public static string Response(string puk) =>
        TransferCode.Encode(Encoding.ASCII.GetBytes(puk));

    /// <summary>Reads a response. Null when the check character disagrees.</summary>
    public static string? ReadResponse(string? code)
    {
        var bytes = TransferCode.Decode(code);

        if (bytes is null || bytes.Length is < 6 or > 8)
        {
            return null;
        }

        var puk = Encoding.ASCII.GetString(bytes);

        return puk.All(char.IsAsciiDigit) ? puk : null;
    }
}

/// <summary>
/// The next PUK, computed the same way on both sides of a telephone.
/// </summary>
/// <remarks>
/// This is what makes an offline unblock leave no lasting secret behind. The
/// server knows the PUK it released and the challenge it answered; the agent
/// knows both as well. Neither has to tell the other what the replacement is —
/// they arrive at it separately, and the value that was spoken aloud stops
/// working the moment the card takes the new one.
/// </remarks>
public static class PukDerivation
{
    /// <summary>Eight digits, the PIV maximum.</summary>
    public static string Next(string currentPuk, string challenge)
    {
        // The challenge is normalised first: it travelled through a person, and
        // "abcd-efgh" and "ABCDEFGH" have to derive the same value.
        var normalised = new string(challenge
            .ToUpperInvariant()
            .Where(char.IsLetterOrDigit)
            .ToArray());

        var mac = HMACSHA256.HashData(
            Encoding.ASCII.GetBytes(currentPuk),
            Encoding.ASCII.GetBytes($"blinky-puk-rotation|{normalised}"));

        var digits = new char[8];

        for (var i = 0; i < digits.Length; i++)
        {
            // One byte per digit, reduced mod 10. The bias is under a fifth of
            // a percent and this is a value nobody guesses at leisure: a wrong
            // PUK costs an attempt and there are three.
            digits[i] = (char)('0' + (mac[i] % 10));
        }

        return new string(digits);
    }
}

/// <summary>What an operator sends to have a response computed.</summary>
public sealed record OfflineUnblockRequest(string Challenge);

/// <summary>
/// The code the operator reads back, and who it is for.
/// </summary>
/// <remarks>
/// The serial travels so the console can show which token this answers before
/// anybody speaks — reading a code back for the wrong token is one wasted PUK
/// attempt on somebody else's card.
/// </remarks>
public sealed record OfflineUnblockResponse(long TokenSerial, string Response);
