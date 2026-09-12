using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;
using Blinky.Api.Secrets;
using Blinky.Secrets;

namespace Blinky.UnitTests;

/// <summary>
/// The abstraction the master secrets moved behind, tested where it does not
/// need a device.
/// </summary>
/// <remarks>
/// Everything here runs against <see cref="ConfigurationKeyProvider"/>, which
/// is the same interface a token answers. What a token adds - non-exportable
/// objects, a PIN, a session that can drop - is in
/// <see cref="Pkcs11KeyProviderTests"/> and needs a module.
/// </remarks>
public class KeyProviderTests
{
    private static byte[] Secret(byte fill)
    {
        var value = new byte[32];
        Array.Fill(value, fill);
        return value;
    }

    private static ConfigurationKeyProvider Provider() =>
        new(new Dictionary<KeyRef, byte[]>
        {
            [new KeyRef(KeyPurpose.ManagementKeyMaster, 1)] = Secret(0x11),
            [new KeyRef(KeyPurpose.PukKek, PukKekVersions.FirstProviderVersion)] = Secret(0x22),
        });

    /// <summary>
    /// A label is derived from purpose and version, so two deployments cannot
    /// name the same key differently.
    /// </summary>
    [Theory]
    [InlineData(KeyPurpose.ManagementKeyMaster, 1, "blinky/management-key/v1")]
    [InlineData(KeyPurpose.ManagementKeyMaster, 4, "blinky/management-key/v4")]
    [InlineData(KeyPurpose.PukKek, 2, "blinky/puk-kek/v2")]
    public void Labels_are_derived(KeyPurpose purpose, int version, string expected)
    {
        Assert.Equal(expected, new KeyRef(purpose, version).Label);
    }

    /// <summary>
    /// One master used for two things is one master whose rotation is blocked
    /// by whichever use is hardest to migrate. They are separate keys, and the
    /// separation has to be real rather than a naming convention.
    /// </summary>
    [Fact]
    public void The_two_purposes_are_different_keys()
    {
        using var provider = Provider();

        var management = provider.Mac(new KeyRef(KeyPurpose.ManagementKeyMaster, 1), "same"u8);
        var envelope = provider.Mac(
            new KeyRef(KeyPurpose.PukKek, PukKekVersions.FirstProviderVersion), "same"u8);

        Assert.NotEqual(management, envelope);
    }

    /// <summary>
    /// There is no way to ask for the key itself, and that is the property the
    /// whole design rests on.
    /// </summary>
    /// <remarks>
    /// Checked by reflection rather than by reading the file, because the thing
    /// being prevented is somebody adding a convenient accessor later. A method
    /// returning key material would make the interface one a device cannot
    /// implement, and the device tier a rewrite.
    /// </remarks>
    [Fact]
    public void The_interface_cannot_hand_out_a_key()
    {
        var forbidden = typeof(IKeyProvider)
            .GetMembers()
            .Select(m => m.Name)
            .Where(name => name.Contains("Export", StringComparison.OrdinalIgnoreCase)
                           || name.Contains("Unwrap", StringComparison.OrdinalIgnoreCase)
                           || name.Contains("Material", StringComparison.OrdinalIgnoreCase)
                           || name.Contains("Bytes", StringComparison.OrdinalIgnoreCase))
            .ToList();

        Assert.Empty(forbidden);
    }

    /// <summary>
    /// HKDF-Expand, and not an approximation of it.
    /// </summary>
    /// <remarks>
    /// Multi-block output is not used by anything today. It is pinned anyway,
    /// because a caller asking for a longer key later would otherwise get
    /// whatever this loop happens to do, and the loop is the sort of thing that
    /// looks right and repeats a block.
    /// </remarks>
    [Theory]
    [InlineData(16)]
    [InlineData(32)]
    [InlineData(48)]
    [InlineData(96)]
    public void Expand_matches_the_standard(int length)
    {
        var master = Secret(0x33);
        var key = new KeyRef(KeyPurpose.ManagementKeyMaster, 1);

        using var provider = new ConfigurationKeyProvider(new Dictionary<KeyRef, byte[]>
        {
            [key] = master,
        });

        var expected = HKDF.Expand(HashAlgorithmName.SHA256,
            HKDF.Extract(HashAlgorithmName.SHA256, master, salt: null),
            length,
            System.Text.Encoding.UTF8.GetBytes("some/info"));

        Assert.Equal(expected, KeyDerivation.Expand(provider, key, "some/info", length));
    }

    /// <summary>
    /// A key that is not there produces a sentence naming it, not a null and
    /// not a zero-filled array.
    /// </summary>
    [Fact]
    public void An_absent_key_is_named()
    {
        using var provider = Provider();

        var missing = new KeyRef(KeyPurpose.ManagementKeyMaster, 9);

        Assert.False(provider.Has(missing));

        var refused = Assert.Throws<KeyUnavailableException>(
            () => provider.Mac(missing, "anything"u8));

        Assert.Contains("blinky/management-key/v9", refused.Message);
    }

    /// <summary>
    /// A secret too short to be one is refused at construction rather than used.
    /// </summary>
    [Fact]
    public void A_short_secret_is_refused()
    {
        var refused = Assert.Throws<KeyUnavailableException>(() =>
            new ConfigurationKeyProvider(new Dictionary<KeyRef, byte[]>
            {
                [new KeyRef(KeyPurpose.ManagementKeyMaster, 1)] = new byte[8],
            }));

        Assert.Contains("32", refused.Message);
    }

    /// <summary>
    /// An empty value is an absent key, because that is how a missing
    /// environment variable presents itself.
    /// </summary>
    [Fact]
    public void An_empty_value_is_an_absent_key()
    {
        using var provider = new ConfigurationKeyProvider(new Dictionary<KeyRef, byte[]>
        {
            [new KeyRef(KeyPurpose.ManagementKeyMaster, 1)] = [],
        });

        Assert.False(provider.Has(new KeyRef(KeyPurpose.ManagementKeyMaster, 1)));
        Assert.Empty(provider.Keys);
    }

    /// <summary>
    /// Configuration is never reported as somewhere a secret is safe.
    /// </summary>
    [Fact]
    public void Configuration_says_it_is_not_production()
    {
        using var provider = Provider();

        Assert.False(provider.Custody.ProductionReady);
        Assert.Contains("environment", provider.Custody.Detail);
    }

    /// <summary>
    /// And says nothing at all about per-key custody, because there is no
    /// device to have asked.
    /// </summary>
    /// <remarks>
    /// This reported false for a while and the console drew a red "exportable —
    /// unprotected" against every key of the default arrangement. True, and
    /// useless: an alarm that fires on the default is one nobody reads, and it
    /// made the case that matters — a token holding a key it would hand out —
    /// indistinguishable from an ordinary laboratory. False now means a device
    /// was asked and said yes.
    /// </remarks>
    [Fact]
    public void Configuration_reports_no_opinion_on_whether_a_key_can_leave()
    {
        using var provider = Provider();

        Assert.All(provider.Keys, key => Assert.Null(key.NonExportable));
    }

    private static IConfiguration Settings(params (string Key, string Value)[] values) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(values.Select(v =>
                new KeyValuePair<string, string?>(v.Key, v.Value)))
            .Build();

    private static readonly string Base64Secret = Convert.ToBase64String(Secret(0x44));

    /// <summary>
    /// A deployment that configures nothing gets what it had before: the
    /// secrets in the environment, the management key at generation one, the
    /// PUK envelopes at the first generation a provider can serve.
    /// </summary>
    [Fact]
    public void The_default_is_the_arrangement_that_existed_before()
    {
        var configuration = Settings(
            ("Blinky:Puk:Kek", Base64Secret),
            ("Blinky:ManagementKey:Master", Base64Secret));

        var options = KeyProviders.Read(configuration);

        Assert.Equal("Configuration", options.Kind);
        Assert.Equal(1, options.ManagementKeyVersion);
        Assert.Equal(PukKekVersions.FirstProviderVersion, options.PukKekVersion);

        using var provider = KeyProviders.Build(configuration, options,
            Microsoft.Extensions.Logging.Abstractions.NullLoggerFactory.Instance);

        Assert.Equal("configuration", provider.Name);
        Assert.True(provider.Has(new KeyRef(KeyPurpose.ManagementKeyMaster, 1)));
        Assert.True(provider.Has(new KeyRef(KeyPurpose.PukKek,
            PukKekVersions.FirstProviderVersion)));
    }

    /// <summary>
    /// No master is still allowed, because docs/06-security.md calls that a
    /// supported state rather than a misconfiguration.
    /// </summary>
    [Fact]
    public void A_deployment_with_no_master_still_starts()
    {
        var configuration = Settings(("Blinky:Puk:Kek", Base64Secret));

        using var provider = KeyProviders.Build(configuration,
            KeyProviders.Read(configuration),
            Microsoft.Extensions.Logging.Abstractions.NullLoggerFactory.Instance);

        Assert.False(provider.Has(new KeyRef(KeyPurpose.ManagementKeyMaster, 1)));
    }

    /// <summary>
    /// Rotating a secret that lives in an environment variable is not rotation,
    /// it is editing the only copy. Refused with the reason.
    /// </summary>
    [Fact]
    public void Configuration_refuses_a_second_generation()
    {
        var configuration = Settings(
            ("Blinky:Puk:Kek", Base64Secret),
            ("Blinky:Secrets:ManagementKey:Version", "2"));

        var refused = Assert.Throws<InvalidOperationException>(() => KeyProviders.Build(
            configuration, KeyProviders.Read(configuration),
            Microsoft.Extensions.Logging.Abstractions.NullLoggerFactory.Instance));

        Assert.Contains("Pkcs11", refused.Message);
    }

    /// <summary>
    /// Generation one of the PUK KEK names the raw configured value used as a
    /// cipher key, which no provider can serve. Configuring it as the one to
    /// write with would produce envelopes nothing could open.
    /// </summary>
    [Fact]
    public void The_legacy_puk_generation_cannot_be_selected()
    {
        var refused = Assert.Throws<InvalidOperationException>(() => KeyProviders.Read(
            Settings(("Blinky:Secrets:PukKek:Version", "1"))));

        Assert.Contains("must be at least", refused.Message);
    }
}
