using Blinky.Secrets;

namespace Blinky.Api.Secrets;

/// <summary>
/// The management key for one token, derived rather than stored.
/// </summary>
/// <remarks>
/// <para>
/// Two properties, and both are in docs/06-security.md as promises this code
/// has to keep. A stolen database yields no management key, because none is
/// written down. And a key extracted from one token opens that token only,
/// because the serial goes into the derivation.
/// </para>
/// <para>
/// So this is a function, not a table. Nothing here reads or writes anything;
/// the same master and the same serial give the same key on any machine, for
/// as long as the master exists — which is also the whole risk, and why the
/// master belongs behind <see cref="IKeyProvider"/> rather than in a byte array
/// this class holds.
/// </para>
/// <para>
/// The derivation is HKDF-Expand over a domain string, which is what it always
/// was: for a 32-byte output, <c>HKDF.DeriveKey(master, info)</c> is one HMAC
/// block under the extract of that master, so a deployment that imports the
/// extract of the master it already has keeps every card's key unchanged. The
/// extract half moved out of this file because it cannot be performed by a
/// device holding the master as a key — see <see cref="KeyDerivation"/>, where
/// that is explained and where the equality is pinned by a test.
/// </para>
/// </remarks>
public sealed class ManagementKeyDerivation(IKeyProvider provider, int version)
{
    private readonly KeyRef key = new(KeyPurpose.ManagementKeyMaster, version);

    /// <summary>
    /// Long enough for every management key algorithm PIV defines: AES-256 is
    /// the largest at 32 bytes, and the agent takes what its own card needs.
    /// </summary>
    /// <remarks>
    /// Sent whole rather than cut to size here, because the length depends on
    /// what the card reports and only the agent has asked it. Truncating HKDF
    /// output is sound - that is what its counter mode is for.
    /// </remarks>
    public const int SecretLength = 32;

    /// <summary>
    /// Which generation of the master this derives from.
    /// </summary>
    /// <remarks>
    /// Recorded against the token when a key is handed out, so that a rotation
    /// is a new version beside the old one and a job per card, rather than a
    /// fleet nobody can tell apart. <c>Token.ManagementKeyVersion</c> is the
    /// column this lands in.
    /// </remarks>
    public int Version => key.Version;

    /// <summary>Whether a master is configured at all.</summary>
    /// <remarks>
    /// A deployment without one keeps the factory key, which is the state every
    /// card is in today. Worth being able to say so out loud rather than
    /// failing at the first write.
    /// </remarks>
    public bool IsConfigured => provider.Has(key);

    /// <summary>The key material for one token.</summary>
    /// <remarks>
    /// The serial is rendered as decimal text rather than as bytes so that the
    /// value is reproducible from a printed serial number by hand, in the
    /// situation where somebody has to.
    /// </remarks>
    /// <param name="generation">
    /// Which master to derive from, for a card that was diversified under an
    /// older one. Omitted means the generation this deployment writes with.
    /// </param>
    /// <remarks>
    /// A rotation is a new generation beside the old one, so a card is only
    /// manageable for as long as the master it was personalised under is still
    /// held. That is why the provider looks for every generation up to the
    /// configured one, and why this takes the card's, not the deployment's.
    /// </remarks>
    public byte[] For(long serial, int? generation = null)
    {
        var wanted = generation is { } version && version != key.Version
            ? new KeyRef(KeyPurpose.ManagementKeyMaster, version)
            : key;

        if (!provider.Has(wanted))
        {
            throw new InvalidOperationException(
                $"No management key master is configured for {wanted.Label}, so no key can be "
                + "derived. See MANAGEMENT_KEY_MASTER in .env, or provision the key into the "
                + "token with scripts/new-secret-keys.sh.");
        }

        var info = string.Create(System.Globalization.CultureInfo.InvariantCulture,
            $"{wanted.Domain}/{serial}");

        return KeyDerivation.Expand(provider, wanted, info, SecretLength);
    }
}
