namespace Blinky.Secrets;

/// <summary>
/// Where Blinky's long-lived secrets live, and the only place they are used.
/// </summary>
/// <remarks>
/// <para>
/// Shaped after PKCS#11 rather than after a byte array, for the same reason
/// <c>ICaKeyStore</c> is: the operation happens behind this interface and the
/// key is never handed out. There is deliberately no <c>Export</c>, no
/// <c>GetBytes</c> and no property returning key material - not because a
/// caller could not be trusted with it, but because an interface that can
/// return a key is an interface a device cannot implement, and then the device
/// tier is a rewrite instead of a configuration change.
/// </para>
/// <para>
/// One primitive, and it is enough. Both of Blinky's secrets are roots of a
/// key-derivation function, so both reduce to a keyed MAC over a domain string.
/// A second mechanism - authenticated encryption inside the device - was the
/// obvious alternative and was rejected: support for it varies between PKCS#11
/// providers and its parameters changed meaning between v2.40 and v3.0, while
/// HMAC-SHA256 is answered by everything that calls itself a token. Adding an
/// operation later is additive; discovering that the device cannot do the one
/// operation everything depends on is not.
/// </para>
/// <para>
/// What this does <b>not</b> protect: the derived value. A management key has
/// to reach the card and a PUK has to reach the person unblocking it, so both
/// exist in this process for as long as the request takes. The boundary this
/// interface draws is around the root - the thing whose loss is permanent and
/// fleet-wide - and drawing it anywhere else would be a claim the product
/// cannot keep.
/// </para>
/// </remarks>
public interface IKeyProvider : IDisposable
{
    /// <summary>
    /// What answered, for the console and the logs. "configuration",
    /// "pkcs11", and never a vendor name inferred from a module path.
    /// </summary>
    string Name { get; }

    /// <summary>How these keys are held, in terms an operator can act on.</summary>
    KeyCustody Custody { get; }

    /// <summary>
    /// The keys this provider actually found, checked at start rather than at
    /// first use.
    /// </summary>
    /// <remarks>
    /// A deployment whose device is reachable but whose token holds no key for
    /// a purpose should say so on the status page, not during somebody's
    /// enrolment.
    /// </remarks>
    IReadOnlyCollection<KeyDescription> Keys { get; }

    /// <summary>
    /// A keyed MAC over <paramref name="data"/>, computed where the key lives.
    /// </summary>
    /// <remarks>
    /// HMAC-SHA256, so the output is always 32 bytes. The caller supplies the
    /// full input including any domain separation and counter byte, because
    /// the derivation is the caller's contract with its own past output and
    /// this layer must not be free to change it.
    /// </remarks>
    /// <exception cref="KeyUnavailableException">
    /// The key is not present, or the device refused. Both are the same thing
    /// to a caller: this operation cannot be performed and the reason belongs
    /// in the message.
    /// </exception>
    byte[] Mac(KeyRef key, ReadOnlySpan<byte> data);

    /// <summary>Whether a given key is present and usable.</summary>
    bool Has(KeyRef key);
}

/// <summary>What is known about one key, without any of its material.</summary>
/// <param name="NonExportable">
/// That the device says the key cannot leave it. Read from the object rather
/// than assumed from the provider type, because a token can be provisioned
/// wrongly and look identical from the outside.
/// <para>
/// <b>Null where there is no device to ask</b>, which is the whole reason this
/// is not a plain bool. A configuration value is of course extractable, so
/// answering false is true and useless: it fires the alarm on the default
/// arrangement, and an alarm that fires on the default is one nobody reads.
/// Worse, it makes the case that matters - a token holding a key it would hand
/// out, the interface of a device with the custody of a file - look identical
/// to an ordinary laboratory. False means a device was asked and said yes.
/// </para>
/// </param>
public sealed record KeyDescription(KeyRef Key, string Label, bool? NonExportable);

/// <summary>
/// How the long-lived secrets are held.
/// </summary>
/// <remarks>
/// The same distinction <c>KeyCustody</c> draws for the CA key in
/// <c>Blinky.Pki</c>, kept separate here on purpose: they are two questions
/// with two answers, and a deployment can perfectly well hold the CA key in a
/// device while its management-key master is still in a file. They converge
/// when the CA key moves onto the same provider, and that is the point at which
/// merging them costs nothing.
/// </remarks>
/// <param name="ProductionReady">
/// Whether this arrangement is one to run a real deployment on. Three states
/// would be more honest than two and the console renders <see cref="Detail"/>
/// for exactly that reason.
/// </param>
public sealed record KeyCustody(string Tier, string Description, bool ProductionReady, string Detail);

/// <summary>
/// The operation cannot be performed, and the reason is worth reading.
/// </summary>
/// <remarks>
/// A refusal rather than a fault. A deployment with no master configured is a
/// supported state per docs/06-security.md, and a device that is unreachable is
/// an operations problem - neither should reach a caller as a null.
/// </remarks>
public sealed class KeyUnavailableException(string message, Exception? inner = null)
    : Exception(message, inner);
