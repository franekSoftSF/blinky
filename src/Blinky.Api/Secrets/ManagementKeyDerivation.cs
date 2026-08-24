using System.Security.Cryptography;
using System.Text;

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
/// master belongs in an HSM once there is one.
/// </para>
/// <para>
/// HKDF rather than a hash of the two values concatenated. A plain
/// <c>SHA256(master || serial)</c> would work today and is the shape that
/// invites a length-extension or a collision between "serial 1" followed by
/// something and "serial 12" - and the cost of doing it properly is one call.
/// </para>
/// </remarks>
public sealed class ManagementKeyDerivation(byte[] master)
{
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
    /// Separates this use of the master from any other that ever shares it.
    /// </summary>
    private const string Purpose = "blinky/management-key/v1";

    /// <summary>The key material for one token.</summary>
    /// <remarks>
    /// The serial is rendered as decimal text rather than as bytes so that the
    /// value is reproducible from a printed serial number by hand, in the
    /// situation where somebody has to.
    /// </remarks>
    public byte[] For(long serial)
    {
        if (master.Length == 0)
        {
            throw new InvalidOperationException(
                "No management key master is configured, so no key can be derived. "
                + "See MANAGEMENT_KEY_MASTER in .env.");
        }

        var info = Encoding.UTF8.GetBytes(
            $"{Purpose}/{serial.ToString(System.Globalization.CultureInfo.InvariantCulture)}");

        return HKDF.DeriveKey(HashAlgorithmName.SHA256, master, SecretLength, salt: null, info);
    }

    /// <summary>Whether a master is configured at all.</summary>
    /// <remarks>
    /// A deployment without one keeps the factory key, which is the state every
    /// card is in today. Worth being able to say so out loud rather than
    /// failing at the first write.
    /// </remarks>
    public bool IsConfigured => master.Length > 0;
}
