using Blinky.Api.Authorities;
using Blinky.Domain;
using Blinky.Domain.Entities;
using Blinky.Pki.Adcs;
using Microsoft.Extensions.Configuration;

namespace Blinky.UnitTests;

/// <summary>
/// CAs and profiles as rows (0108): what a row may hold, and the CA built from it.
/// </summary>
public sealed class CertificateAuthorityRowsTests
{
    private static readonly IConfiguration Empty = new ConfigurationBuilder().Build();

    [Fact]
    public void A_password_typed_as_a_value_never_reaches_the_row()
    {
        var options = new AdcsInstanceOptions { Transport = "ConnectorPolls" };
        options.Connector.ClientCertificatePassword = "hunter2";
        options.EnrolmentAgent.Password = "hunter3";
        options.Templates["smartcard-logon"] = "BlinkySmartCardLogon";

        var stored = CertificateAuthorities.Serialise(options);

        Assert.DoesNotContain("hunter2", stored, StringComparison.Ordinal);
        Assert.DoesNotContain("hunter3", stored, StringComparison.Ordinal);

        // The template belongs to the profile; a copy on the CA is how they would disagree.
        Assert.DoesNotContain("BlinkySmartCardLogon", stored, StringComparison.Ordinal);
    }

    [Fact]
    public void A_polling_microsoft_ca_is_built_from_its_row_with_the_ca_name_it_was_given()
    {
        var options = new AdcsInstanceOptions { Transport = "ConnectorPolls" };
        options.Connector.CaConfig = @"SUBCA\DigitalWorkspace Issuing CA - homelab";

        var row = new CaInstance
        {
            Name = "digitalworkspace",
            Backend = CaBackend.Adcs,
            Configuration = CertificateAuthorities.Serialise(options),
        };

        var built = CertificateAuthorities.Build(row, [Profile("smartcard-logon", "BlinkySmartCardLogon", row)],
            Empty, new ConnectorQueue());

        var adcs = Assert.IsType<AdcsCertificateAuthority>(built);
        Assert.Equal("digitalworkspace", adcs.Name);
        Assert.NotNull(adcs.Connector);
        Assert.Equal(@"SUBCA\DigitalWorkspace Issuing CA - homelab",
            CertificateAuthorities.AdcsSettingsOf(row).Connector.CaConfig);
    }

    [Theory]
    [InlineData("rsa2048", "Rsa2048")]
    [InlineData("ECCP256", "EccP256")]
    [InlineData(" EccP384 ", "EccP384")]
    public void A_key_algorithm_is_stored_as_the_agent_spells_it(string given, string stored)
    {
        Assert.Equal(stored, CaAdministration.KeyAlgorithm(given));
    }

    [Theory]
    [InlineData("Ed25519")]
    [InlineData("TripleDes")]
    [InlineData("")]
    public void Anything_a_card_cannot_generate_for_a_certificate_is_refused(string given)
    {
        var refusal = Assert.Throws<CaAdministrationException>(() => CaAdministration.KeyAlgorithm(given));
        Assert.Equal(400, refusal.Status);
    }

    [Fact]
    public void A_profile_cannot_require_a_key_used_without_a_pin()
    {
        // The agent refuses PIN policy Never for a logon key, so a profile asking for it
        // would describe a card nothing can produce.
        Assert.DoesNotContain("Never", CaAdministration.PinPolicies);
        Assert.Contains("Once", CaAdministration.PinPolicies);
        Assert.Contains("Never", CaAdministration.TouchPolicies);
    }

    private static CertificateProfile Profile(string name, string template, CaInstance ca) => new()
    {
        Name = name,
        CaInstance = ca,
        SlotId = "9A",
        KeyAlgorithm = "Rsa2048",
        ValidityDays = 365,
        AdcsTemplateName = template,
        IsEnabled = true,
    };
}
