using Blinky.Api.Credentials;
using Blinky.Pki;

namespace Blinky.UnitTests;

/// <summary>
/// What the console is told a profile is, and what the CA is then asked to
/// issue, come from one list.
/// </summary>
/// <remarks>
/// They used to come from two: <c>ByName</c> held the certificate facts in a
/// switch, and anything that wanted to describe a profile - a dropdown, a
/// dialog explaining why a person cannot be issued to - had to restate them.
/// A copy of a policy is a copy that drifts, and this one drifts silently:
/// nothing fails until a certificate is issued under rules the page did not
/// know about.
/// <para>
/// So the descriptors are the list and <c>ByName</c> builds from them. These
/// cases exist to keep it that way.
/// </para>
/// </remarks>
public class ProfileCatalogueTests
{
    [Fact]
    public void Every_profile_issues_what_it_advertises()
    {
        Assert.NotEmpty(Profiles.All);

        foreach (var descriptor in Profiles.All)
        {
            var issued = Profiles.ByName(descriptor.Name, "9A");

            Assert.Equal(descriptor.Name, issued.Name);
            Assert.Equal(descriptor.KeyAlgorithm, issued.KeyAlgorithm);
            Assert.Equal(descriptor.ValidityDays, issued.ValidityDays);
            Assert.Equal(descriptor.ExtendedKeyUsages, issued.ExtendedKeyUsages);
            Assert.Equal(descriptor.IncludeUpnSan, issued.IncludeUpnSan);
            Assert.Equal(descriptor.IncludeSidExtension, issued.IncludeSidExtension);
        }
    }

    /// <summary>
    /// A slot belongs to an enrolment, not to a profile.
    /// </summary>
    /// <remarks>
    /// Worth asserting because the slot used to arrive with the certificate
    /// facts, and a list of profiles then cannot be produced without inventing
    /// a slot to ask about - which is how a dropdown ends up quietly offering
    /// everything as if it were 9A.
    /// </remarks>
    [Fact]
    public void The_slot_is_the_only_thing_a_profile_learns_from_its_caller()
    {
        foreach (var descriptor in Profiles.All)
        {
            var authentication = Profiles.ByName(descriptor.Name, "9A");
            var signature = Profiles.ByName(descriptor.Name, "9C");

            Assert.Equal("9A", authentication.SlotId);
            Assert.Equal("9C", signature.SlotId);
            Assert.Equal(authentication with { SlotId = "9C" }, signature);
        }
    }

    /// <summary>
    /// The rule a console cannot do without: which profile demands a SID.
    /// </summary>
    /// <remarks>
    /// <c>smartcard-logon</c> refuses to issue without a resolved
    /// <c>objectSid</c> because since KB5014754 a domain controller ignores a
    /// certificate mapped by name alone. <c>client-auth</c> exists precisely
    /// so there is something to issue when no SID has been resolved, and it is
    /// deliberately missing both the Smart Card Logon usage and the UPN, so it
    /// cannot be mistaken for a logon credential.
    /// </remarks>
    [Fact]
    public void Only_the_logon_profile_demands_an_identity()
    {
        var logon = Profiles.DescriptorByName(Profiles.SmartCardLogon);
        var clientAuth = Profiles.DescriptorByName(Profiles.ClientAuthentication);

        Assert.NotNull(logon);
        Assert.True(logon.IncludeSidExtension);
        Assert.True(logon.IncludeUpnSan);
        Assert.Contains(Blinky.Pki.BuiltIn.BuiltInCertificateAuthority.SmartCardLogonOid,
            logon.ExtendedKeyUsages);

        Assert.NotNull(clientAuth);
        Assert.False(clientAuth.IncludeSidExtension);
        Assert.False(clientAuth.IncludeUpnSan);
        Assert.DoesNotContain(Blinky.Pki.BuiltIn.BuiltInCertificateAuthority.SmartCardLogonOid,
            clientAuth.ExtendedKeyUsages);
    }

    /// <summary>
    /// Asking whether a name is a profile is a question; issuing under a name
    /// that is not one is a failure. They get different answers.
    /// </summary>
    /// <remarks>
    /// The endpoint that validates an operator's request needs the first, and
    /// catching a policy exception to produce a 400 would read as though
    /// something had gone wrong when nothing had.
    /// </remarks>
    [Fact]
    public void An_unknown_name_is_null_to_a_question_and_a_refusal_to_an_issuance()
    {
        Assert.Null(Profiles.DescriptorByName("no-such-profile"));

        var refused = Assert.Throws<IssuancePolicyException>(
            () => Profiles.ByName("no-such-profile", "9A"));

        Assert.Contains("no-such-profile", refused.Message, StringComparison.Ordinal);
    }
}
