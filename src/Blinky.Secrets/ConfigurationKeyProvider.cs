using System.Security.Cryptography;

namespace Blinky.Secrets;

/// <summary>
/// The secrets in configuration, which is where every deployment starts.
/// </summary>
/// <remarks>
/// <para>
/// This is the arrangement Blinky has today, given the shape it will have
/// tomorrow: the same derivations, the same values, the same wire, and the
/// keys still in the environment of the process that uses them. It exists so
/// that a deployment without a device is a provider choice rather than a
/// different code path, and so that the device path is exercised by every test
/// that does not need a device.
/// </para>
/// <para>
/// Reported as not production ready, every time. An environment variable is
/// visible in <c>docker inspect</c>, in a crash dump, in a process listing and
/// in whatever collects those - which is a different exposure from a file, and
/// worse than one, and the console should not make the two look alike.
/// </para>
/// <para>
/// The material is extracted once at construction rather than used raw. That
/// makes this provider hold exactly what a device would hold after
/// <c>--import-master</c>, so the two produce identical output and a migration
/// changes nothing a card can see. See <see cref="KeyDerivation"/>.
/// </para>
/// </remarks>
public sealed class ConfigurationKeyProvider : IKeyProvider
{
    private readonly Dictionary<KeyRef, byte[]> keys = [];

    /// <param name="material">
    /// The configured secret per key. An entry whose value is empty is treated
    /// as absent, because "the variable exists and is blank" is how a missing
    /// secret usually presents itself.
    /// </param>
    public ConfigurationKeyProvider(IReadOnlyDictionary<KeyRef, byte[]> material)
    {
        ArgumentNullException.ThrowIfNull(material);

        foreach (var (key, secret) in material)
        {
            if (secret.Length == 0)
            {
                continue;
            }

            if (secret.Length < 32)
            {
                throw new KeyUnavailableException(
                    $"The secret configured for {key.Label} is {secret.Length} bytes; 32 is the "
                    + "minimum. Generate one with: openssl rand -base64 32");
            }

            keys[key] = HKDF.Extract(HashAlgorithmName.SHA256, secret, salt: null);
        }
    }

    public string Name => "configuration";

    public KeyCustody Custody { get; } = new(
        Tier: "Configuration",
        Description: "the process environment",
        ProductionReady: false,
        "The master secrets are configuration values held by this process. They are readable "
        + "wherever its environment is readable, which includes container inspection, crash "
        + "dumps and anything that collects either. Correct for a laboratory, and the thing to "
        + "change first before it is not one.");

    public IReadOnlyCollection<KeyDescription> Keys => keys.Keys
        .Select(k => new KeyDescription(k, k.Label, NonExportable: false))
        .ToList();

    public bool Has(KeyRef key) => keys.ContainsKey(key);

    public byte[] Mac(KeyRef key, ReadOnlySpan<byte> data)
    {
        if (!keys.TryGetValue(key, out var secret))
        {
            throw new KeyUnavailableException(
                $"No secret is configured for {key.Label}, so nothing can be derived from it.");
        }

        return HMACSHA256.HashData(secret, data);
    }

    public void Dispose()
    {
        foreach (var secret in keys.Values)
        {
            CryptographicOperations.ZeroMemory(secret);
        }

        keys.Clear();
    }
}
