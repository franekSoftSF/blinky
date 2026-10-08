using System.Security.Cryptography;
using System.Text;
using Blinky.Domain.Entities;
using Blinky.Secrets;

namespace Blinky.Api.Passkeys;

/// <summary>
/// Seals and opens a passkey provider's credential.
/// </summary>
/// <remarks>
/// <para>
/// The PUK envelope's scheme, in a domain of its own: AES-256-GCM under a key
/// derived (HKDF over the key provider's MAC) from the PUK KEK, the provider's id,
/// the credential kind and the nonce. Deriving a second purpose from one root is
/// what HKDF's info string is for; a separate root would have meant a third key in
/// every deployment's PKCS#11 token and in every <c>.env</c>, for no separation
/// the derivation does not already give.
/// </para>
/// <para>
/// The id and the kind are authenticated, not encrypted: a ciphertext copied to
/// another provider's row, or relabelled as another kind of credential, fails to
/// open instead of opening as somebody else's secret.
/// </para>
/// </remarks>
public sealed class ProviderSecrets(IKeyProvider provider, int version)
{
    private const string Domain = "passkey-provider";

    public void Seal(PasskeyProvider row, PasskeyProviderCredential kind, string plaintext)
    {
        var key = new KeyRef(KeyPurpose.PukKek, version);
        var nonce = RandomNumberGenerator.GetBytes(AesGcm.NonceByteSizes.MaxSize);
        var bytes = Encoding.UTF8.GetBytes(plaintext);
        var ciphertext = new byte[bytes.Length];
        var tag = new byte[AesGcm.TagByteSizes.MaxSize];
        var envelopeKey = Key(key, row.Id, kind, nonce);

        try
        {
            using var aes = new AesGcm(envelopeKey, tag.Length);
            aes.Encrypt(nonce, bytes, ciphertext, tag, Associated(row.Id, kind));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(envelopeKey);
            CryptographicOperations.ZeroMemory(bytes);
        }

        row.CredentialKind = kind;
        row.SecretCiphertext = ciphertext;
        row.SecretNonce = nonce;
        row.SecretTag = tag;
        row.SecretKeyVersion = version;
    }

    /// <returns>The plaintext, for as long as it takes to build the provider from it.</returns>
    public string Open(PasskeyProvider row)
    {
        if (row is not { CredentialKind: { } kind, SecretCiphertext: { } ciphertext, SecretNonce: { } nonce,
                SecretTag: { } tag, SecretKeyVersion: { } keyVersion })
        {
            throw new InvalidOperationException($"Passkey provider {row.Name} has no credential set.");
        }

        var plaintext = new byte[ciphertext.Length];
        var envelopeKey = Key(new KeyRef(KeyPurpose.PukKek, keyVersion), row.Id, kind, nonce);

        try
        {
            using var aes = new AesGcm(envelopeKey, tag.Length);
            aes.Decrypt(nonce, ciphertext, tag, plaintext, Associated(row.Id, kind));
            return Encoding.UTF8.GetString(plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(envelopeKey);
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private static byte[] Associated(Guid id, PasskeyProviderCredential kind) =>
        Encoding.ASCII.GetBytes($"{Domain}|{id:N}|{kind}");

    private byte[] Key(KeyRef key, Guid id, PasskeyProviderCredential kind, byte[] nonce)
    {
        if (!provider.Has(key))
        {
            throw new InvalidOperationException(
                $"No key-encryption key is available for {key.Label}; passkey provider credentials are "
                + "sealed under the same root as escrowed PUKs.");
        }

        return KeyDerivation.Expand(provider, key,
            $"{key.Domain}|{Domain}|{id:N}|{kind}|{Convert.ToHexString(nonce)}", 32);
    }
}
