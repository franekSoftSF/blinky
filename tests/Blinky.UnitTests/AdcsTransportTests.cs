using Blinky.AdcsConnector;
using Blinky.Contracts;

namespace Blinky.UnitTests;

/// <summary>
/// The wire between the API and a connector installed on somebody else's CA,
/// and the two things the connector reads out of a request before it lets it
/// reach ADCS.
/// </summary>
public sealed class AdcsTransportTests
{
    [Theory]
    [InlineData(0, false)]
    [InlineData(1, true)]
    [InlineData(2, false)]
    public void A_version_this_build_does_not_speak_is_refused(int version, bool supported) =>
        Assert.Equal(supported, AdcsTransport.IsSupported(version));

    [Fact]
    public void The_transport_version_is_its_own_and_not_the_agent_protocol()
    {
        // Two ends that upgrade on different change windows. Tying the
        // connector's version to the agent's would mean a container upgrade
        // silently demanding work on a Windows server nobody here can reach.
        Assert.Equal(AdcsTransport.MaximumSupportedVersion, AdcsTransport.SchemaVersion);
        Assert.True(AdcsTransport.MinimumSupportedVersion <= AdcsTransport.SchemaVersion);
    }

    [Theory]
    // CR_DISP_*, and the numbers are Microsoft's. If these drift, a denied
    // request reads as issued.
    [InlineData(AdcsDisposition.Incomplete, 0)]
    [InlineData(AdcsDisposition.Error, 1)]
    [InlineData(AdcsDisposition.Denied, 2)]
    [InlineData(AdcsDisposition.Issued, 3)]
    [InlineData(AdcsDisposition.IssuedOutOfBand, 4)]
    [InlineData(AdcsDisposition.UnderSubmission, 5)]
    [InlineData(AdcsDisposition.Revoked, 6)]
    public void A_disposition_keeps_the_value_the_ca_gave_it(
        AdcsDisposition disposition, int value) =>
        Assert.Equal(value, (int)disposition);

    [Theory]
    [InlineData("CertificateTemplate:BlinkySmartcardUser", "BlinkySmartcardUser")]
    [InlineData("certificatetemplate: BlinkySmartcardUser ", "BlinkySmartcardUser")]
    [InlineData("SAN:upn=nobody@blinky.lab\nCertificateTemplate:Other", "Other")]
    [InlineData("SAN:upn=nobody@blinky.lab", null)]
    [InlineData("CertificateTemplate:", null)]
    [InlineData(null, null)]
    public void The_template_is_read_out_of_the_attribute_string(
        string? attributes, string? expected) =>
        Assert.Equal(expected, ConnectorEndpoints.TemplateIn(attributes));

    [Theory]
    [InlineData("1a2b3c", true)]
    [InlineData("00", true)]
    [InlineData("", false)]
    [InlineData(null, false)]
    [InlineData("1a 2b", false)]
    [InlineData("61003b0000", true)]
    [InlineData("'; drop", false)]
    public void A_serial_number_is_hex_and_nothing_else(string? value, bool accepted) =>
        Assert.Equal(accepted, ConnectorEndpoints.IsSerial(value));

    [Theory]
    // Reached nothing: RPC server unavailable, call failed, no endpoint; a CA
    // that is not found; a bad network path.
    [InlineData(0x800706BAu, true)]
    [InlineData(0x800706BEu, true)]
    [InlineData(0x800706D9u, true)]
    [InlineData(0x80070002u, true)]
    [InlineData(0x80070035u, true)]
    // Access denied is its own answer, and a CA error means the call arrived.
    [InlineData(0x80070005u, false)]
    [InlineData(0x80094004u, false)]
    public void A_probe_that_never_reached_a_ca_is_not_read_as_revocation_being_available(
        uint hresult, bool neverReached) =>
        // On HZCS01 an RPC failure against a CA that did not exist was read as
        // the call having got as far as the database, and the connector reported
        // revocation as available.
        Assert.Equal(neverReached, CertificateServices.NeverReachedTheCa(hresult));
}
