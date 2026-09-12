using Blinky.Secrets;

namespace Blinky.Api.Secrets;

/// <summary>
/// Builds the key provider this deployment is configured for, once, at start.
/// </summary>
/// <remarks>
/// <para>
/// The only place in the API that knows there is more than one kind. Above
/// this, everything takes an <see cref="IKeyProvider"/> and cannot tell a
/// configuration value from a device - which is the whole point, and the thing
/// that makes adding a YubiHSM a change to a compose file.
/// </para>
/// <para>
/// At start rather than lazily, because a token that is unreachable or a PIN
/// that is wrong should stop a deployment coming up rather than surface as a
/// failed enrolment an hour later. The one exception is a missing
/// management-key master, which docs/06-security.md calls a supported state.
/// </para>
/// </remarks>
public static class KeyProviders
{
    /// <summary>
    /// What the configuration asks for, before anything is opened.
    /// </summary>
    /// <remarks>
    /// Read separately from <see cref="Build"/> because the versions are needed
    /// to register services and opening a device is not. Nothing here touches a
    /// module, so a deployment with an unplugged token still fails on the
    /// device rather than on a settings typo.
    /// </remarks>
    /// <param name="LegacyPukKek">
    /// The raw configured KEK, kept for opening version one PUK envelopes.
    /// Empty in a deployment that never wrote any.
    /// </param>
    public sealed record SecretsOptions(
        string Kind,
        int ManagementKeyVersion,
        int PukKekVersion,
        byte[] LegacyPukKek);

    public static SecretsOptions Read(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var pukVersion = configuration.GetValue(
            "Blinky:Secrets:PukKek:Version", PukKekVersions.FirstProviderVersion);

        if (pukVersion <= PukKekVersions.Legacy)
        {
            throw new InvalidOperationException(
                "Blinky:Secrets:PukKek:Version must be at least "
                + $"{PukKekVersions.FirstProviderVersion}. Version {PukKekVersions.Legacy} names "
                + "the configured KEK used directly as a cipher key, which is the arrangement "
                + "this replaced and which no provider can serve.");
        }

        return new SecretsOptions(
            configuration["Blinky:Secrets:Provider"] ?? "Configuration",
            configuration.GetValue("Blinky:Secrets:ManagementKey:Version", 1),
            pukVersion,
            Decode(configuration, "Blinky:Puk:Kek"));
    }

    public static IKeyProvider Build(IConfiguration configuration, SecretsOptions options,
        ILoggerFactory loggers)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(loggers);

        var provider = options.Kind.Equals("Pkcs11", StringComparison.OrdinalIgnoreCase)
            ? Pkcs11(configuration, options.ManagementKeyVersion, options.PukKekVersion)
            : FromConfiguration(configuration, options.ManagementKeyVersion, options.PukKekVersion,
                options.LegacyPukKek);

        // Wrapped last, so that nothing reaches a device without being counted,
        // and so that there is one answer to "what is safe to write down".
        var audit = loggers.CreateLogger("Blinky.Secrets");

        return new AuditingKeyProvider(provider, use => Announce(audit, use));
    }

    /// <summary>
    /// One line per use of a master secret, with neither the input nor the
    /// output in it.
    /// </summary>
    /// <remarks>
    /// Information rather than warning: this happens once per enrolment and
    /// once per unblock, and a warning that fires on the normal path stops
    /// being read. The thing worth alerting on is the failure count, which the
    /// status endpoint reports.
    /// </remarks>
    private static void Announce(ILogger logger, KeyUse use)
    {
        if (use.Failure is null)
        {
            logger.LogInformation(
                "{Provider} computed {Operation} with {Key} over {Bytes} bytes in {Elapsed}",
                use.Provider, use.Operation, use.Key.Label, use.InputBytes, use.Elapsed);

            return;
        }

        logger.LogError(
            "{Provider} refused {Operation} with {Key}: {Reason}",
            use.Provider, use.Operation, use.Key.Label, use.Failure);
    }

    private static IKeyProvider Pkcs11(IConfiguration configuration,
        int managementVersion, int pukVersion)
    {
        var options = new Pkcs11KeyProviderOptions
        {
            Module = configuration["Blinky:Secrets:Pkcs11:Module"] ?? string.Empty,
            TokenLabel = configuration["Blinky:Secrets:Pkcs11:TokenLabel"] ?? "blinky",
            PinFile = configuration["Blinky:Secrets:Pkcs11:PinFile"],
            Pin = configuration["Blinky:Secrets:Pkcs11:Pin"],
            ManagementKeyVersion = managementVersion,
            PukKekVersion = pukVersion,
            RequireNonExportable = configuration.GetValue(
                "Blinky:Secrets:Pkcs11:RequireNonExportable", true),
        };

        return new Pkcs11KeyProvider(options);
    }

    /// <summary>
    /// The secrets as they are configured today, in the shape they will have
    /// tomorrow.
    /// </summary>
    /// <remarks>
    /// The version numbers are fixed here and that is deliberate: rotating a
    /// secret held in an environment variable is not rotation, it is editing
    /// the only copy. A deployment that wants a second generation of either key
    /// wants a provider that can hold two.
    /// </remarks>
    private static IKeyProvider FromConfiguration(IConfiguration configuration,
        int managementVersion, int pukVersion, byte[] legacyKek)
    {
        if (managementVersion != 1 || pukVersion != PukKekVersions.FirstProviderVersion)
        {
            throw new InvalidOperationException(
                "The configuration provider holds one generation of each secret, so "
                + "Blinky:Secrets:ManagementKey:Version must be 1 and "
                + $"Blinky:Secrets:PukKek:Version must be {PukKekVersions.FirstProviderVersion}. "
                + "Rotating to a second generation needs a provider that can hold both at once: "
                + "set Blinky:Secrets:Provider to Pkcs11.");
        }

        if (legacyKek.Length == 0)
        {
            throw new InvalidOperationException(
                "Blinky:Puk:Kek is not set. PUK escrow needs a 32-byte key, base64 encoded; "
                + "generate one with: openssl rand -base64 32");
        }

        if (legacyKek.Length != 32)
        {
            throw new InvalidOperationException(
                $"Blinky:Puk:Kek decodes to {legacyKek.Length} bytes; AES-256 needs 32.");
        }

        var master = Decode(configuration, "Blinky:ManagementKey:Master");

        if (master.Length is > 0 and < 32)
        {
            throw new InvalidOperationException(
                $"Blinky:ManagementKey:Master decodes to {master.Length} bytes; 32 is the "
                + "minimum. Generate one with: openssl rand -base64 32");
        }

        return new ConfigurationKeyProvider(new Dictionary<KeyRef, byte[]>
        {
            [new KeyRef(KeyPurpose.ManagementKeyMaster, 1)] = master,

            // The same bytes the version one envelopes used, now serving as a
            // derivation root instead of as a cipher key. A deployment upgrading
            // in place therefore needs no new secret, and its existing envelopes
            // keep opening through the legacy path.
            [new KeyRef(KeyPurpose.PukKek, PukKekVersions.FirstProviderVersion)] = legacyKek,
        });
    }

    private static byte[] Decode(IConfiguration configuration, string path)
    {
        var configured = configuration[path];

        if (string.IsNullOrWhiteSpace(configured))
        {
            return [];
        }

        try
        {
            return Convert.FromBase64String(configured);
        }
        catch (FormatException e)
        {
            throw new InvalidOperationException(
                $"{path} is not valid base64. Generate one with: openssl rand -base64 32", e);
        }
    }
}
