using Blinky.Agent.Service;
using Blinky.Contracts;
using Microsoft.Extensions.Logging.Abstractions;

namespace Blinky.UnitTests;

/// <summary>
/// The refusals an agent makes before it touches anything. The job engine
/// proper - leases, the watchdog, a job surviving an agent that dies - runs
/// against the real stack; these are the decisions taken before any of that.
/// </summary>
public sealed class JobExecutorTests
{
    [Fact]
    public async Task A_job_from_a_newer_server_is_refused_with_the_range_this_agent_speaks()
    {
        // Half-understanding a job is worse than refusing it: the server would
        // be told work had started that this agent cannot finish.
        var executor = Executor();
        var job = new JobEnvelope(Protocol.MaximumSupportedVersion + 1, Guid.NewGuid(),
            JobType.Inventory, "k", DateTimeOffset.UtcNow.AddHours(1), null,
            [new JobStep("ReadAllReaders")]);

        var result = await executor.ExecuteAsync(job, Backend(), 1, CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Contains("protocol", result.Detail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task An_unknown_step_is_refused_before_any_step_runs()
    {
        // Checked up front, so a job cannot be announced as started and then
        // abandoned halfway. Reaching the backend at all would fail this test,
        // which is the point: nothing is reported before the whole list is
        // understood.
        var executor = Executor();
        var job = new JobEnvelope(Protocol.SchemaVersion, Guid.NewGuid(), JobType.Enroll, "k",
            DateTimeOffset.UtcNow.AddHours(1), 29177301,
            [new JobStep("ReadAllReaders"), new JobStep("DiverisfyManagementKey")]);

        var result = await executor.ExecuteAsync(job, Backend(), 1, CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Equal("DiverisfyManagementKey", result.FailedStep);
        Assert.Contains("UnsupportedOperation", result.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void The_supported_operations_are_stated_rather_than_discovered()
    {
        Assert.Contains("ReadAllReaders", JobExecutor.Supported);
    }

    [Fact]
    public void An_inventory_envelope_carries_the_identifier_it_was_given()
    {
        // The row's identifier and the envelope's have to be the same one. When
        // they were not, the agent reported progress against a job that did not
        // exist, the server refused it, and the work was done while the row sat
        // claimed until the watchdog took it back.
        var id = Guid.NewGuid();

        var envelope = JobEnvelope.Inventory(id, "inventory:x", DateTimeOffset.UtcNow.AddHours(1));

        Assert.Equal(id, envelope.JobId);
        Assert.Equal(JobType.Inventory, envelope.Type);
        Assert.Equal(Protocol.SchemaVersion, envelope.SchemaVersion);
    }

    private static JobExecutor Executor() =>
        new(new InventoryCollector(NullLogger<InventoryCollector>.Instance),
            NullLogger<JobExecutor>.Instance);

    /// <summary>
    /// Never used by these cases: both refusals happen before the first call.
    /// </summary>
    private static BackendClient Backend() => new(new Uri("https://localhost:9443"));
}
