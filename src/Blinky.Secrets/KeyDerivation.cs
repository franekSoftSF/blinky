using System.Text;

namespace Blinky.Secrets;

/// <summary>
/// HKDF-Expand, with the MAC performed wherever the key lives.
/// </summary>
/// <remarks>
/// <para>
/// The extract half of HKDF is deliberately absent, and that absence is the
/// whole reason this file exists. Extract computes <c>HMAC(salt, master)</c> -
/// the master is the <i>message</i>, not the key - so it cannot be performed by
/// a device holding the master as a key object. The way out is not to export
/// the master; it is to keep the pseudorandom key that extract produces as the
/// thing the device holds, which RFC 5869 section 3.3 permits explicitly for
/// input that is already uniformly random. Blinky's masters are read from a
/// cryptographic source, so they are.
/// </para>
/// <para>
/// The consequence is the good one: for a 32-byte output this is one HMAC
/// block, and <c>HMAC(extract(master), info || 0x01)</c> is bit-for-bit what
/// <c>HKDF.DeriveKey(master, info)</c> returned before any of this existed.
/// A deployment migrating to a device imports the extract of the master it
/// already has and every card keeps the same management key. See
/// <c>scripts/new-secret-keys.sh --import-master</c> and the test that pins the
/// equality.
/// </para>
/// </remarks>
public static class KeyDerivation
{
    /// <summary>The output of HMAC-SHA256, which is the block size here.</summary>
    private const int MacLength = 32;

    /// <summary>
    /// Derives <paramref name="length"/> bytes for one <paramref name="info"/>.
    /// </summary>
    /// <param name="info">
    /// The domain string. Built by the caller from the key's own domain and
    /// whatever makes this derivation unique - a token serial, an envelope
    /// nonce - so that two purposes sharing a key can never collide.
    /// </param>
    public static byte[] Expand(IKeyProvider provider, KeyRef key, string info, int length)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(length);

        // 255 blocks is HKDF's own ceiling and nothing here comes close; the
        // check is present so that a future caller asking for more gets a
        // sentence rather than a truncated key.
        ArgumentOutOfRangeException.ThrowIfGreaterThan(length, MacLength * 255);

        var infoBytes = Encoding.UTF8.GetBytes(info);
        var output = new byte[length];
        var written = 0;
        var previous = Array.Empty<byte>();

        for (byte counter = 1; written < length; counter++)
        {
            var block = new byte[previous.Length + infoBytes.Length + 1];
            previous.CopyTo(block, 0);
            infoBytes.CopyTo(block, previous.Length);
            block[^1] = counter;

            previous = provider.Mac(key, block);

            var take = Math.Min(previous.Length, length - written);
            previous.AsSpan(0, take).CopyTo(output.AsSpan(written));
            written += take;
        }

        return output;
    }
}
