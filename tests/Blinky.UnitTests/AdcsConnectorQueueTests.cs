using System.Net;
using System.Text.Json;
using Blinky.Contracts;
using Blinky.Pki;
using Blinky.Pki.Adcs;

namespace Blinky.UnitTests;

/// <summary>
/// The connector dialling the API: the same transport, the same contract and the same
/// refusals as the API dialling the connector, with a queue where the socket was.
/// </summary>
public sealed class AdcsConnectorQueueTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    [Fact]
    public async Task A_call_is_collected_answered_and_read_by_the_same_transport()
    {
        var queue = new ConnectorQueue();
        using var transport = new ConnectorAdcsTransport(queue, caConfig: @"SUBCA\Issuing");

        var connector = Task.Run(async () =>
        {
            var item = await queue.NextAsync(TimeSpan.FromSeconds(5), default);

            Assert.NotNull(item);
            Assert.Equal("GET", item.Method);
            Assert.StartsWith("/connector/describe", item.Path, StringComparison.Ordinal);
            Assert.Contains("SUBCA", Uri.UnescapeDataString(item.Path), StringComparison.Ordinal);

            var answer = new AdcsDescribeResponse(
                AdcsTransport.SchemaVersion, "test", @"SUBCA\Issuing", "Issuing", AdminAvailable: true);

            Assert.True(queue.Complete(new AdcsWorkResult(
                AdcsTransport.SchemaVersion, item.Id, 200, JsonSerializer.Serialize(answer, Json))));
        });

        var described = await transport.DescribeAsync();
        await connector;

        Assert.Equal(@"SUBCA\Issuing", described.CaConfig);
        Assert.True(described.AdminAvailable);
        Assert.NotNull(queue.LastPoll);
    }

    [Fact]
    public async Task No_connector_asking_fails_in_the_pickup_time_and_says_none_ever_asked()
    {
        var queue = new ConnectorQueue { PickupTimeout = TimeSpan.FromMilliseconds(100) };
        using var transport = new ConnectorAdcsTransport(queue, caConfig: null);

        var refusal = await Assert.ThrowsAsync<CertificateAuthorityException>(() => transport.DescribeAsync());

        Assert.Contains("None has asked for work", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_call_nobody_collected_in_time_is_never_handed_out_afterwards()
    {
        // The case that matters is a signature: an agent that gave up must not have
        // its PKIData signed by a connector that arrives a minute later.
        var queue = new ConnectorQueue { PickupTimeout = TimeSpan.FromMilliseconds(50) };
        using var transport = new ConnectorAdcsTransport(queue, caConfig: null);

        await Assert.ThrowsAsync<CertificateAuthorityException>(() => transport.SignPkiDataAsync([1, 2, 3]));

        Assert.Null(await queue.NextAsync(TimeSpan.FromMilliseconds(100), default));
    }

    [Fact]
    public async Task A_refusal_from_the_connector_reads_the_way_it_does_over_a_socket()
    {
        var queue = new ConnectorQueue();
        using var transport = new ConnectorAdcsTransport(queue, caConfig: null);

        var connector = Task.Run(async () =>
        {
            var item = (await queue.NextAsync(TimeSpan.FromSeconds(5), default))!;

            queue.Complete(new AdcsWorkResult(
                AdcsTransport.SchemaVersion, item.Id, (int)HttpStatusCode.BadRequest,
                JsonSerializer.Serialize(new AdcsProblem("The PKIData carries a control other than RegInfo."), Json)));
        });

        var refusal = await Assert.ThrowsAsync<CertificateAuthorityException>(() => transport.SignPkiDataAsync([1]));
        await connector;

        Assert.Contains("answered 400", refusal.Message, StringComparison.Ordinal);
        Assert.Contains("other than RegInfo", refusal.Message, StringComparison.Ordinal);
        Assert.Contains("polling this API", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_collected_call_left_unanswered_says_the_ca_may_have_issued_anyway()
    {
        var queue = new ConnectorQueue { AnswerTimeout = TimeSpan.FromMilliseconds(100) };
        using var transport = new ConnectorAdcsTransport(queue, caConfig: null);

        var connector = queue.NextAsync(TimeSpan.FromSeconds(5), default);

        var refusal = await Assert.ThrowsAsync<CertificateAuthorityException>(
            () => transport.SubmitAsync([1], AdcsRequestFormat.Cmc, "CertificateTemplate:X"));

        var item = await connector;

        Assert.Contains("issued at the CA all the same", refusal.Message, StringComparison.Ordinal);

        // Too late: nobody is waiting, and the connector is told so rather than
        // believing it delivered a certificate.
        Assert.False(queue.Complete(new AdcsWorkResult(AdcsTransport.SchemaVersion, item!.Id, 200, "{}")));
    }

    [Fact]
    public async Task Describes_asked_together_reach_the_connector_once_and_are_reused_afterwards()
    {
        // BY-CACMS: the console's status page asked several times a second, every
        // describe queued behind the last, and the answers took four seconds.
        var queue = new ConnectorQueue();
        using var transport = new ConnectorAdcsTransport(queue, caConfig: null);

        var asked = Enumerable.Range(0, 8).Select(_ => transport.DescribeAsync()).ToArray();

        var item = (await queue.NextAsync(TimeSpan.FromSeconds(5), default))!;
        queue.Complete(new AdcsWorkResult(AdcsTransport.SchemaVersion, item.Id, 200, JsonSerializer.Serialize(
            new AdcsDescribeResponse(AdcsTransport.SchemaVersion, "test", "CA", "CA", AdminAvailable: true), Json)));

        await Task.WhenAll(asked);
        await transport.DescribeAsync();

        Assert.Null(await queue.NextAsync(TimeSpan.FromMilliseconds(100), default));
    }

    [Fact]
    public async Task A_describe_that_failed_is_asked_again_rather_than_remembered()
    {
        var queue = new ConnectorQueue
        {
            PickupTimeout = TimeSpan.FromMilliseconds(50),
            AnswerTimeout = TimeSpan.FromMilliseconds(50),
        };
        using var transport = new ConnectorAdcsTransport(queue, caConfig: null);

        await Assert.ThrowsAsync<CertificateAuthorityException>(() => transport.DescribeAsync());

        var again = transport.DescribeAsync();
        Assert.NotNull(await queue.NextAsync(TimeSpan.FromSeconds(5), default));

        await Assert.ThrowsAnyAsync<Exception>(() => again);
    }

    [Fact]
    public void An_answer_for_a_call_that_was_never_handed_out_is_refused() =>
        Assert.False(new ConnectorQueue().Complete(
            new AdcsWorkResult(AdcsTransport.SchemaVersion, Guid.NewGuid(), 200, "{}")));

    [Fact]
    public void A_polled_ca_in_a_process_with_no_queue_is_refused_by_name()
    {
        var options = new AdcsInstanceOptions { Transport = "ConnectorPolls" };

        var refusal = Assert.Throws<CertificateAuthorityException>(() => AdcsInstance.Create(options, issues: false));

        Assert.Contains("Only the API answers a connector", refusal.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("/api/adcs/connector/next", true)]
    [InlineData("/API/ADCS/CONNECTOR/result", true)]
    [InlineData("/api/adcs/connectorx", false)]
    [InlineData("/api/jobs/next", false)]
    public void The_connector_routes_are_told_apart_from_the_agent_routes(string path, bool connector) =>
        Assert.Equal(connector, Blinky.Api.Security.ConnectorIdentities.IsConnectorRoute(new Microsoft.AspNetCore.Http.PathString(path)));

    /// <summary>
    /// Every workstation's certificate chains to the agent CA too, so the
    /// registration is what tells one of them from a connector - and since
    /// 0102 the registration is a row rather than a line in .env.
    /// </summary>
    [Fact]
    public void A_certificate_from_the_same_ca_is_a_connector_only_by_its_registration()
    {
        using var connector = AdcsTestCertificates.Agent();
        using var workstation = AdcsTestCertificates.Agent();

        var registered = Blinky.Api.Security.ConnectorIdentities.FingerprintOf(connector);

        Assert.Equal(64, registered.Length);
        Assert.NotEqual(registered, Blinky.Api.Security.ConnectorIdentities.FingerprintOf(workstation));

        var row = new Blinky.Domain.Entities.ConnectorRegistration { Fingerprint = registered };

        Assert.True(row.IsActive);

        row.RevokedAt = DateTime.UtcNow;

        // Withdrawn from the console, and refused on the next call rather than
        // after a restart: that is the whole reason this stopped being config.
        Assert.False(row.IsActive);
    }

    [Fact]
    public void A_polled_ca_builds_without_a_url_or_a_client_certificate()
    {
        var options = new AdcsInstanceOptions { Name = "lab-adcs", Transport = "ConnectorPolls" };

        using var ca = AdcsInstance.Create(options, issues: true, new ConnectorQueue());

        Assert.Equal("lab-adcs", ca.Name);
        Assert.Contains("polling this API", ca.AgentDescription, StringComparison.Ordinal);
    }
}
