using System.Security.Cryptography;
using System.Text;
using Blinky.Api.Secrets;
using Blinky.Secrets;

namespace Blinky.UnitTests;

/// <summary>
/// The provider against a real PKCS#11 module.
/// </summary>
/// <remarks>
/// <para>
/// Skipped where no module is installed, which includes CI. That is recorded in
/// docs/STATUS.md rather than hidden: a test that passes by not running is
/// worse than one that says it did not.
/// </para>
/// <para>
/// The fixture is per-class rather than shared, because each of these wants a
/// token in a known state and a scratch store costs a few milliseconds.
/// </para>
/// </remarks>
public class Pkcs11KeyProviderTests
{
    private static readonly KeyRef Generated = new(KeyPurpose.ManagementKeyMaster, 1);
    private static readonly KeyRef Imported = new(KeyPurpose.PukKek, 2);

    private static Pkcs11KeyProviderOptions Options(Pkcs11TestToken token,
        bool requireNonExportable = true, int managementVersion = 1) =>
        new()
        {
            Module = token.Module,
            TokenLabel = Pkcs11TestToken.TokenLabel,
            Pin = Pkcs11TestToken.UserPin,
            ManagementKeyVersion = managementVersion,
            PukKekVersion = 2,
            RequireNonExportable = requireNonExportable,
        };

    [RequiresPkcs11Module]
    public void The_token_is_opened_and_its_keys_found()
    {
        using var token = new Pkcs11TestToken();
        using var provider = new Pkcs11KeyProvider(Options(token));

        Assert.Equal("pkcs11", provider.Name);
        Assert.True(provider.Has(Generated));
        Assert.True(provider.Has(Imported));

        Assert.All(provider.Keys, key => Assert.True(key.NonExportable));
        Assert.True(provider.Custody.ProductionReady);
    }

    /// <summary>
    /// The same input gives the same answer, which is the only property a
    /// derivation root needs and the one a broken session would break.
    /// </summary>
    [RequiresPkcs11Module]
    public void The_token_computes_a_stable_mac()
    {
        using var token = new Pkcs11TestToken();
        using var provider = new Pkcs11KeyProvider(Options(token));

        var once = provider.Mac(Generated, "blinky/management-key/v1/23673995"u8);
        var twice = provider.Mac(Generated, "blinky/management-key/v1/23673995"u8);

        Assert.Equal(32, once.Length);
        Assert.Equal(once, twice);
        Assert.NotEqual(once, provider.Mac(Generated, "blinky/management-key/v1/29051525"u8));
    }

    /// <summary>
    /// <b>The migration proof.</b> A deployment that imports the extract of the
    /// master it already has gets, from inside the token, exactly the values
    /// the configuration provider produced outside it.
    /// </summary>
    /// <remarks>
    /// This is what makes moving an existing deployment onto a device a
    /// provisioning step rather than a job per card. Without it the honest
    /// answer would be a re-key of every token in the fleet, and the argument
    /// for doing it at all would be much weaker.
    /// </remarks>
    [RequiresPkcs11Module]
    public void An_imported_master_reproduces_the_configured_one()
    {
        using var token = new Pkcs11TestToken();
        using var device = new Pkcs11KeyProvider(Options(token));

        using var configured = new ConfigurationKeyProvider(new Dictionary<KeyRef, byte[]>
        {
            [Imported] = Pkcs11TestToken.ImportedMaster,
        });

        var info = "blinky/puk-kek/v2|puk|23673995|AABB";

        Assert.Equal(
            KeyDerivation.Expand(configured, Imported, info, 32),
            KeyDerivation.Expand(device, Imported, info, 32));
    }

    /// <summary>
    /// And end to end: a management key derived through the token is the value
    /// the deployment was writing before any of this existed.
    /// </summary>
    [RequiresPkcs11Module]
    public void A_management_key_from_the_token_is_the_value_cards_already_hold()
    {
        using var token = new Pkcs11TestToken();
        using var device = new Pkcs11KeyProvider(Options(token));

        // The imported key sits under the PUK purpose in the fixture, so this
        // asserts the arithmetic rather than the label: what a card holds is
        // HKDF over the old master, and what the token computes has to match it
        // for the same domain string.
        const long serial = 23673995;

        var before = HKDF.DeriveKey(HashAlgorithmName.SHA256, Pkcs11TestToken.ImportedMaster,
            ManagementKeyDerivation.SecretLength, salt: null,
            Encoding.UTF8.GetBytes($"{Imported.Domain}/{serial}"));

        var now = KeyDerivation.Expand(device, Imported, $"{Imported.Domain}/{serial}",
            ManagementKeyDerivation.SecretLength);

        Assert.Equal(before, now);
    }

    /// <summary>
    /// A key the token will hand out is refused, because the interface of a
    /// device with the custody of a file should not report as a device.
    /// </summary>
    [RequiresPkcs11Module]
    public void An_extractable_key_is_refused()
    {
        using var token = new Pkcs11TestToken();

        var refused = Assert.Throws<KeyUnavailableException>(
            () => new Pkcs11KeyProvider(Options(token, managementVersion: 9)));

        Assert.Contains("extractable", refused.Message, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// And accepted when the deployment says so out loud, reported for what it
    /// is rather than as a device.
    /// </summary>
    [RequiresPkcs11Module]
    public void An_extractable_key_can_be_accepted_deliberately()
    {
        using var token = new Pkcs11TestToken();
        using var provider = new Pkcs11KeyProvider(
            Options(token, requireNonExportable: false, managementVersion: 9));

        Assert.False(provider.Custody.ProductionReady);
        Assert.Contains(provider.Keys, key =>
            key.Label == Pkcs11TestToken.ExtractableLabel && !key.NonExportable);
    }

    /// <summary>
    /// A generation that was never provisioned is a sentence naming it, not a
    /// key that silently is not there.
    /// </summary>
    [RequiresPkcs11Module]
    public void A_missing_key_is_named()
    {
        using var token = new Pkcs11TestToken();
        using var provider = new Pkcs11KeyProvider(Options(token));

        var absent = new KeyRef(KeyPurpose.ManagementKeyMaster, 4);

        Assert.False(provider.Has(absent));

        var refused = Assert.Throws<KeyUnavailableException>(
            () => provider.Mac(absent, "anything"u8));

        Assert.Contains("blinky/management-key/v4", refused.Message);
    }

    /// <summary>
    /// A token label nothing answers to fails at construction with the labels
    /// that were actually there.
    /// </summary>
    [RequiresPkcs11Module]
    public void A_token_that_is_not_there_is_refused_at_start()
    {
        using var token = new Pkcs11TestToken();

        var options = new Pkcs11KeyProviderOptions
        {
            Module = token.Module,
            TokenLabel = "not-this-one",
            Pin = Pkcs11TestToken.UserPin,
        };

        var refused = Assert.Throws<KeyUnavailableException>(() => new Pkcs11KeyProvider(options));

        Assert.Contains("not-this-one", refused.Message);
        Assert.Contains(Pkcs11TestToken.TokenLabel, refused.Message);
    }

    /// <summary>
    /// A module path that is not a file says so, rather than failing somewhere
    /// inside a P/Invoke.
    /// </summary>
    [Fact]
    public void A_module_that_is_not_there_is_refused_at_start()
    {
        var refused = Assert.Throws<KeyUnavailableException>(() => new Pkcs11KeyProvider(
            new Pkcs11KeyProviderOptions { Module = "/nowhere/libnothing.so", Pin = "1" }));

        Assert.Contains("/nowhere/libnothing.so", refused.Message);
    }

    /// <summary>
    /// No PIN at all is refused before the module is loaded, so the failure is
    /// a sentence about configuration rather than one from inside a P/Invoke.
    /// </summary>
    /// <remarks>
    /// The module here is a file that exists and is not a PKCS#11 library,
    /// which is the only way to reach the PIN check without a module installed.
    /// </remarks>
    [Fact]
    public void A_missing_pin_is_refused_before_the_module_is_loaded()
    {
        var anyFile = typeof(Pkcs11KeyProviderTests).Assembly.Location;

        var refused = Assert.Throws<KeyUnavailableException>(() => new Pkcs11KeyProvider(
            new Pkcs11KeyProviderOptions { Module = anyFile }));

        Assert.Contains("PinFile", refused.Message);
    }

    /// <summary>
    /// The whole path, as the API assembles it: a provider, an audit decorator
    /// and a derivation, with the values landing where a card expects them.
    /// </summary>
    [RequiresPkcs11Module]
    public void The_derivation_works_through_the_audit_decorator()
    {
        using var token = new Pkcs11TestToken();
        var seen = new List<KeyUse>();

        using var provider = new AuditingKeyProvider(
            new Pkcs11KeyProvider(Options(token)), seen.Add);

        var derivation = new ManagementKeyDerivation(provider, version: 1);

        Assert.True(derivation.IsConfigured);
        Assert.Equal(32, derivation.For(23673995).Length);

        var use = Assert.Single(seen);

        Assert.Equal("pkcs11", use.Provider);
        Assert.Null(use.Failure);
    }
}
