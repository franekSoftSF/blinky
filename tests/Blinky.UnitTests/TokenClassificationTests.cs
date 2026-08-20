using Blinky.Api.Tokens;
using Blinky.Contracts;
using Blinky.Domain;

namespace Blinky.UnitTests;

/// <summary>
/// The rules that turn an agent's facts into a token's state. These decide
/// whether a token can be personalised at all, so they are tested away from the
/// database that stores their answers.
/// </summary>
public sealed class TokenClassificationTests
{
    [Fact]
    public void A_bio_token_with_no_puk_is_not_applicable_rather_than_disabled()
    {
        // The distinction the personalisation policy rests on. A Bio ships
        // without a PUK; treating that as a broken token would refuse an entire
        // product line at first contact.
        var noPuk = new CredentialReport(IsDefault: null, IsBlocked: false,
            RemainingRetries: 0, TotalRetries: 0);
        var biometrics = new BiometricReport(FingerprintsEnrolled: true, AttemptsRemaining: 3,
            TemporaryPinSet: false);

        Assert.Equal(CredentialSecretState.NotApplicable,
            TokenClassification.Puk(noPuk, biometrics));
    }

    [Fact]
    public void Any_other_token_with_no_puk_is_disabled()
    {
        // Same bytes from the card, opposite meaning: somebody removed the
        // recovery path from an ordinary token and nobody recorded why.
        var noPuk = new CredentialReport(IsDefault: null, IsBlocked: false,
            RemainingRetries: 0, TotalRetries: 0);

        Assert.Equal(CredentialSecretState.Disabled,
            TokenClassification.Puk(noPuk, biometrics: null));
    }

    [Fact]
    public void No_retries_left_is_not_the_same_as_no_puk()
    {
        // Zero remaining out of three is a blocked PUK, which an operator can
        // still do something about. Zero out of zero is no PUK at all.
        var blocked = new CredentialReport(IsDefault: false, IsBlocked: true,
            RemainingRetries: 0, TotalRetries: 3);

        Assert.Equal(CredentialSecretState.Blocked,
            TokenClassification.Puk(blocked, biometrics: null));
    }

    [Theory]
    [InlineData(true, false, nameof(CredentialSecretState.Default))]
    [InlineData(false, false, nameof(CredentialSecretState.Set))]
    [InlineData(false, true, nameof(CredentialSecretState.Blocked))]
    public void A_pin_is_classified_from_what_the_card_said(bool isDefault, bool isBlocked,
        string expected)
    {
        var pin = new CredentialReport(isDefault, isBlocked, RemainingRetries: 3, TotalRetries: 3);

        Assert.Equal(expected, TokenClassification.Pin(pin).ToString());
    }

    [Fact]
    public void A_pin_on_firmware_that_cannot_be_asked_is_unknown_not_set()
    {
        // Below firmware 5.3 there is no GET METADATA. An operator needs to see
        // the difference between a PIN that is not set and one nobody could ask
        // about.
        Assert.Equal(CredentialSecretState.Unknown,
            TokenClassification.Pin(CredentialReport.Unknown));
    }

    [Fact]
    public void A_token_without_biometrics_is_not_supported_rather_than_not_enrolled()
    {
        Assert.Equal(BiometricState.NotSupported, TokenClassification.Biometrics(null));
    }

    [Theory]
    [InlineData(true, 3, nameof(BiometricState.Enrolled))]
    [InlineData(true, 0, nameof(BiometricState.Blocked))]
    [InlineData(false, 3, nameof(BiometricState.NotEnrolled))]
    public void Biometric_state_follows_enrolment_and_attempts(bool enrolled, int attempts,
        string expected)
    {
        var report = new BiometricReport(enrolled, attempts, TemporaryPinSet: false);

        Assert.Equal(expected, TokenClassification.Biometrics(report).ToString());
    }

    [Fact]
    public void A_management_key_we_never_diversified_and_is_not_default_is_lost()
    {
        // Neither the factory value nor a version we recorded: no key
        // generation, no certificate write. That has to show up in a list, not
        // in a failed job.
        var key = new ManagementKeyReport("Aes192", IsDefault: false, TouchPolicy: "Never");

        Assert.Equal(ManagementKeyState.Lost, TokenClassification.ManagementKey(key, 0));
    }

    [Fact]
    public void A_management_key_at_a_version_we_recorded_is_diversified()
    {
        var key = new ManagementKeyReport("Aes192", IsDefault: false, TouchPolicy: "Never");

        Assert.Equal(ManagementKeyState.Diversified, TokenClassification.ManagementKey(key, 1));
    }

    [Fact]
    public void A_factory_management_key_is_default_whatever_version_we_hold()
    {
        var key = new ManagementKeyReport("TripleDes", IsDefault: true, TouchPolicy: "Never");

        Assert.Equal(ManagementKeyState.Default, TokenClassification.ManagementKey(key, 7));
    }

    [Fact]
    public void Firmware_too_old_to_report_a_management_key_is_unknown()
    {
        Assert.Equal(ManagementKeyState.Unknown, TokenClassification.ManagementKey(null, 0));
    }
}
