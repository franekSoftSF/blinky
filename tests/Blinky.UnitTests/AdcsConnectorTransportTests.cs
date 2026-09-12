using System.Net;
using System.Text;
using System.Text.Json;
using Blinky.Contracts;
using Blinky.Pki;
using Blinky.Pki.Adcs;

namespace Blinky.UnitTests;

/// <summary>
/// The container's half of the connector wire.
/// </summary>
/// <remarks>
/// No socket and no connector: a stub handler stands in, which is enough for
/// everything except TLS. What travels here is a CMC already signed by the
/// enrolment agent, so the failures worth testing are the ones a deployment
/// actually produces - a rotated client certificate, a connector nobody
/// upgraded, and a WAF answering in HTML.
/// </remarks>
public sealed class AdcsConnectorTransportTests
{
    private static readonly Uri Connector = new("https://ca01.blinky.lab:8444");

    private static ConnectorTransportOptions Options(string? caConfig = null) =>
        new(Connector, CaConfig: caConfig);

    private static ConnectorAdcsTransport Transport(
        StubHandler handler, string? caConfig = null) =>
        new(Options(caConfig), handler);

    [Fact]
    public async Task Every_call_carries_the_schema_version_in_a_header()
    {
        var handler = StubHandler.Returning(Describe());
        using var transport = Transport(handler);

        await transport.DescribeAsync();

        Assert.Equal(
            AdcsTransport.SchemaVersion.ToString(),
            handler.LastRequest!.Headers.GetValues(AdcsTransport.SchemaHeader).Single());
    }

    [Fact]
    public async Task A_connector_speaking_a_version_this_build_does_not_know_is_refused()
    {
        var handler = StubHandler.Returning(Describe(schema: 9, version: "0.9.0+abc"));
        using var transport = Transport(handler);

        var refusal = await Assert.ThrowsAsync<CertificateAuthorityException>(
            () => transport.DescribeAsync());

        // Named with both versions and the connector's own, because this is the
        // one mismatch nothing in this repository can fix: the connector is
        // upgraded by whoever owns the CA server.
        Assert.Contains("speaks schema 9", refusal.Message, StringComparison.Ordinal);
        Assert.Contains("0.9.0+abc", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_ca_config_travels_as_a_query_on_describe_and_in_the_body_elsewhere()
    {
        var handler = StubHandler.Returning(Describe());
        using var transport = Transport(handler, caConfig: @"CA01\Lab Issuing CA");

        await transport.DescribeAsync();

        Assert.Contains(
            "caConfig=CA01%5CLab%20Issuing%20CA",
            handler.LastRequest!.RequestUri!.Query,
            StringComparison.Ordinal);

        handler.Next = Submitted();
        await transport.SubmitAsync([1, 2, 3], AdcsRequestFormat.Cmc, null);

        Assert.Contains(@"CA01\\Lab Issuing CA", handler.LastBody!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_submission_sends_the_request_as_base64_and_the_format_as_a_name()
    {
        var handler = StubHandler.Returning(Submitted());
        using var transport = Transport(handler);

        await transport.SubmitAsync([0xDE, 0xAD, 0xBE, 0xEF], AdcsRequestFormat.Cmc,
            "CertificateTemplate:BlinkySmartcardUser");

        var sent = JsonSerializer.Deserialize<AdcsSubmitRequest>(
            handler.LastBody!, new JsonSerializerOptions(JsonSerializerDefaults.Web))!;

        Assert.Equal(AdcsTransport.SchemaVersion, sent.SchemaVersion);
        Assert.Equal(Convert.ToBase64String([0xDE, 0xAD, 0xBE, 0xEF]), sent.Request);
        Assert.Equal(AdcsRequestFormat.Cmc, sent.Format);
        Assert.Equal("CertificateTemplate:BlinkySmartcardUser", sent.Attributes);

        // As a name on the wire, so that whoever reads the body in a terminal on
        // the CA server can see what was asked for.
        Assert.Contains("\"Cmc\"", handler.LastBody!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_issued_answer_comes_back_whole()
    {
        var handler = StubHandler.Returning(Submitted(requestId: 42, certificate: "AAEC"));
        using var transport = Transport(handler);

        var answer = await transport.SubmitAsync([1], AdcsRequestFormat.Cmc, null);

        Assert.Equal(AdcsDisposition.Issued, answer.Disposition);
        Assert.Equal(42, answer.RequestId);
        Assert.Equal("AAEC", answer.Certificate);
    }

    [Fact]
    public async Task Revoking_sends_the_serial_and_the_reason_code()
    {
        var handler = StubHandler.Returning(Json(new AdcsRevokeResponse(true)));
        using var transport = Transport(handler);

        var answer = await transport.RevokeAsync("1a2b3c", 4, null);

        Assert.True(answer.Revoked);

        var sent = JsonSerializer.Deserialize<AdcsRevokeRequest>(
            handler.LastBody!, new JsonSerializerOptions(JsonSerializerDefaults.Web))!;

        Assert.Equal("1a2b3c", sent.SerialNumber);
        Assert.Equal(4, sent.Reason);
    }

    [Fact]
    public async Task A_rejected_client_certificate_says_where_to_add_its_fingerprint()
    {
        var handler = StubHandler.Returning(Json(
            new AdcsProblem("The client certificate is not one this connector was told to accept."),
            HttpStatusCode.Forbidden));

        using var transport = Transport(handler);

        var refusal = await Assert.ThrowsAsync<CertificateAuthorityException>(
            () => transport.SubmitAsync([1], AdcsRequestFormat.Cmc, null));

        // The predictable deployment failure, and not a fault at the CA: the
        // certificate was rotated here and not there.
        Assert.Contains("AllowedClientThumbprints", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_connectors_own_reason_is_carried_rather_than_replaced()
    {
        var handler = StubHandler.Returning(Json(
            new AdcsProblem(
                "CA01\\Lab Issuing CA refused the request: The request subject name is invalid "
                + "or too long.",
                "0x80094001"),
            HttpStatusCode.BadGateway));

        using var transport = Transport(handler);

        var failure = await Assert.ThrowsAsync<CertificateAuthorityException>(
            () => transport.SubmitAsync([1], AdcsRequestFormat.Cmc, null));

        Assert.Contains("subject name is invalid", failure.Message, StringComparison.Ordinal);
        Assert.Contains("0x80094001", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_error_body_that_is_not_json_falls_back_to_the_status_line()
    {
        // A WAF or a reverse proxy between the container and the CA server
        // answers in HTML. An exception about JSON would hide which of the two
        // refused the call.
        var handler = StubHandler.Returning(new HttpResponseMessage(HttpStatusCode.BadGateway)
        {
            Content = new StringContent("<html><body>502 Bad Gateway</body></html>",
                Encoding.UTF8, "text/html"),
            ReasonPhrase = "Bad Gateway",
        });

        using var transport = Transport(handler);

        var failure = await Assert.ThrowsAsync<CertificateAuthorityException>(
            () => transport.SubmitAsync([1], AdcsRequestFormat.Cmc, null));

        Assert.Contains("502", failure.Message, StringComparison.Ordinal);
        Assert.Contains("Bad Gateway", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_connection_that_never_opened_names_the_two_things_it_usually_is()
    {
        var handler = StubHandler.Throwing(new HttpRequestException("No route to host"));
        using var transport = Transport(handler);

        var failure = await Assert.ThrowsAsync<CertificateAuthorityException>(
            () => transport.DescribeAsync());

        Assert.Contains("No route to host", failure.Message, StringComparison.Ordinal);
        Assert.Contains("fingerprint", failure.Message, StringComparison.Ordinal);
        Assert.Contains("firewall", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_timeout_is_not_reported_as_a_cancellation()
    {
        // They arrive as the same exception type, which is how "the CA is not
        // answering" gets logged as "the request was cancelled".
        var handler = StubHandler.Throwing(new TaskCanceledException("The operation timed out"));
        using var transport = Transport(handler);

        var failure = await Assert.ThrowsAsync<CertificateAuthorityException>(
            () => transport.DescribeAsync());

        Assert.Contains("did not answer", failure.Message, StringComparison.Ordinal);
        Assert.Contains("serialises calls", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_success_with_no_body_is_a_failure_with_a_sentence()
    {
        var handler = StubHandler.Returning(new HttpResponseMessage(HttpStatusCode.NoContent));
        using var transport = Transport(handler);

        var failure = await Assert.ThrowsAsync<CertificateAuthorityException>(
            () => transport.DescribeAsync());

        Assert.Contains("empty or unreadable body", failure.Message, StringComparison.Ordinal);
        Assert.Contains("answered instead of the connector", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_transport_with_no_client_certificate_refuses_to_exist()
    {
        var refusal = Assert.Throws<CertificateAuthorityException>(
            () => new ConnectorAdcsTransport(new ConnectorTransportOptions(
                Connector, ServerFingerprint: new string('a', 64))));

        Assert.Contains("requires a client certificate", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_server_that_cannot_be_identified_is_refused_rather_than_trusted()
    {
        // There is no "accept anything" here, unlike BackendClient. Whoever
        // intercepts a CMC signed by the enrolment agent can submit it to the
        // real CA and collect a certificate in the cardholder's name.
        var refusal = Assert.Throws<CertificateAuthorityException>(
            () => new ConnectorAdcsTransport(new ConnectorTransportOptions(
                Connector, ClientCertificatePath: "client.p12")));

        Assert.Contains("neither pinned by fingerprint nor", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_sha1_thumbprint_in_the_fingerprint_setting_is_refused_by_length()
    {
        // Forty hex digits is the SHA-1 thumbprint from the wrong field of the
        // certificate dialog. Accepting it would mean pinning nothing.
        var refusal = Assert.Throws<CertificateAuthorityException>(
            () => new ConnectorAdcsTransport(new ConnectorTransportOptions(
                Connector,
                ClientCertificatePath: "client.p12",
                ServerFingerprint: "a1 b2 c3 d4 e5 f6 07 18 29 3a 4b 5c 6d 7e 8f 90 a1 b2 c3 d4")));

        Assert.Contains("40 hex digits", refusal.Message, StringComparison.Ordinal);
        Assert.Contains("SHA-1", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void The_description_names_the_connector_so_a_log_says_which_transport_answered() =>
        Assert.Contains(
            "ca01.blinky.lab:8444",
            Transport(StubHandler.Returning(Describe())).Description,
            StringComparison.Ordinal);

    private static HttpResponseMessage Describe(int schema = 1, string version = "0.1.0") =>
        Json(new AdcsDescribeResponse(
            schema, version, @"CA01\Lab Issuing CA", "Lab Issuing CA", AdminAvailable: true));

    private static HttpResponseMessage Submitted(int requestId = 1, string? certificate = "AAEC") =>
        Json(new AdcsSubmitResponse(AdcsDisposition.Issued, requestId, certificate));

    private static HttpResponseMessage Json<T>(T body, HttpStatusCode status = HttpStatusCode.OK) =>
        new(status)
        {
            Content = new StringContent(
                JsonSerializer.Serialize(body, new JsonSerializerOptions(JsonSerializerDefaults.Web)),
                Encoding.UTF8,
                "application/json"),
            ReasonPhrase = status.ToString(),
        };
}

/// <summary>A connector's answers without a connector.</summary>
internal sealed class StubHandler : HttpMessageHandler
{
    private Exception? fault;

    public HttpResponseMessage? Next { get; set; }

    public HttpRequestMessage? LastRequest { get; private set; }

    public string? LastBody { get; private set; }

    public static StubHandler Returning(HttpResponseMessage response) => new() { Next = response };

    public static StubHandler Throwing(Exception exception) => new() { fault = exception };

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        LastRequest = request;

        if (request.Content is not null)
        {
            LastBody = await request.Content.ReadAsStringAsync(cancellationToken);
        }

        if (fault is not null)
        {
            throw fault;
        }

        return Next ?? new HttpResponseMessage(HttpStatusCode.OK);
    }
}
