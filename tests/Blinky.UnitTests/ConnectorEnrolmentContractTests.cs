using System.Text.Json;
using Blinky.Api.Agents;
using Blinky.Api.Security;
using Blinky.Contracts;

namespace Blinky.UnitTests;

/// <summary>
/// The connector's enrolment records against the API's own (0105). Two copies of one
/// shape, because the connector references Contracts and not the API; this is what
/// stops them drifting.
/// </summary>
public sealed class ConnectorEnrolmentContractTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    [Fact]
    public void The_connector_enrols_at_the_route_the_api_leaves_open()
    {
        Assert.Equal(AgentAuthenticationMiddleware.EnrolmentPath, ConnectorEnrolment.Path);
    }

    [Fact]
    public void What_the_connector_sends_is_what_the_api_reads_and_it_says_connector()
    {
        var sent = new ConnectorEnrolmentRequest("MS-CONN01", "ad.digitalworkspace.pl", "tok", "-----BEGIN CERTIFICATE REQUEST-----");

        var read = JsonSerializer.Deserialize<EnrolmentRequest>(JsonSerializer.Serialize(sent, Json), Json)!;

        Assert.Equal(("MS-CONN01", "ad.digitalworkspace.pl", "tok", "-----BEGIN CERTIFICATE REQUEST-----"),
            (read.Hostname, read.Domain, read.BootstrapToken, read.CertificateSigningRequest));

        // The one field that routes it to EnrolConnector rather than to an agent row.
        Assert.Equal("connector", read.Purpose);
    }

    [Fact]
    public void What_the_api_answers_is_what_the_connector_reads()
    {
        var id = Guid.NewGuid();
        var until = new DateTimeOffset(2027, 10, 8, 0, 0, 0, TimeSpan.Zero);
        var answered = new ConnectorEnrolmentResponse(id, "PEM", "CN=Blinky agent CA", until, "AB12");

        var read = JsonSerializer.Deserialize<ConnectorEnrolmentAnswer>(JsonSerializer.Serialize(answered, Json), Json)!;

        Assert.Equal(new ConnectorEnrolmentAnswer(id, "PEM", "CN=Blinky agent CA", until, "AB12"), read);
    }
}
