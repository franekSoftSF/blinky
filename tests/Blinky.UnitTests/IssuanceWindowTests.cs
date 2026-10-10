using System.Text.Json;
using System.Text.RegularExpressions;
using Blinky.Agent.Service;
using Blinky.Contracts;
using Microsoft.Extensions.Logging.Abstractions;

namespace Blinky.UnitTests;

/// <summary>
/// The issuance window of 0084a: one window per job that needs the person,
/// every prompt inside it, and steps it can name.
/// </summary>
/// <remarks>
/// What PC-0001 showed on 2026-10-09 was a PIN prompt and a touch prompt
/// arriving on their own during an enrolment from the console, with nothing
/// saying what was happening. These hold the pieces that stop that: the agent
/// tells the window when a job starts and ends, the step names it reports are
/// the ones the window knows, and every one of them has words in both
/// languages.
/// </remarks>
public sealed class IssuanceWindowTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    private static string RepositoryFile(params string[] parts)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null)
        {
            var candidate = Path.Combine([directory.FullName, .. parts]);

            if (File.Exists(candidate))
            {
                return File.ReadAllText(candidate);
            }

            directory = directory.Parent;
        }

        throw new FileNotFoundException($"Could not find {Path.Combine(parts)} above {AppContext.BaseDirectory}");
    }

    [Fact]
    public void Every_phase_the_enrolment_reports_is_a_step_the_window_knows()
    {
        // A phase reported and not in the list is a step the window passes
        // over in silence - the person sees the bar stop.
        var source = RepositoryFile("src", "Blinky.Agent.Service", "CardEnrolment.cs");

        var reported = Regex.Matches(source, @"Report\(backend, job, attempt, ""(\w+)""")
            .Select(match => match.Groups[1].Value)
            .Distinct()
            .ToList();

        Assert.NotEmpty(reported);
        Assert.Equal([], reported.Except(JobSteps.Enrolment).ToList());
    }

    [Fact]
    public void Every_step_has_a_title_and_an_instruction_in_both_languages()
    {
        var strings = RepositoryFile("src", "Blinky.Agent.Ui", "Strings.cs");
        var polishStart = strings.IndexOf("Dictionary<string, string> Polish", StringComparison.Ordinal);

        Assert.True(polishStart > 0);

        var english = strings[..polishStart];
        var polish = strings[polishStart..];
        var missing = new List<string>();

        foreach (var step in JobSteps.Enrolment.Concat(JobSteps.Passkey))
        {
            foreach (var key in new[] { $"Step.{step}", $"StepHint.{step}" })
            {
                if (!english.Contains($"[\"{key}\"]", StringComparison.Ordinal))
                {
                    missing.Add($"en {key}");
                }

                if (!polish.Contains($"[\"{key}\"]", StringComparison.Ordinal))
                {
                    missing.Add($"pl {key}");
                }
            }
        }

        Assert.Equal([], missing);
    }

    [Fact]
    public void Only_a_job_somebody_takes_part_in_has_steps_to_show()
    {
        Assert.Same(JobSteps.Enrolment, JobSteps.For(JobType.Enroll));
        Assert.Same(JobSteps.Passkey, JobSteps.For(JobType.ProvisionFido2Credential));
        Assert.Null(JobSteps.For(JobType.Inventory));
        Assert.Null(JobSteps.For(JobType.Revoke));
    }

    [Fact]
    public async Task The_window_is_told_when_a_job_starts_and_how_it_ended()
    {
        // Refused before any step runs, so nothing reaches the server - and the
        // window still opens and closes around it, with the reason.
        var window = new RecordingWindow();
        var executor = new JobExecutor(null!, null, null, NullLogger<JobExecutor>.Instance, null, window);
        var context = new JobContext(JobContext.EnrolCard, "Jan Kowalski", "jan@ad.example", "helpdesk1", "smartcard-logon");
        var job = new JobEnvelope(Protocol.SchemaVersion, Guid.NewGuid(), JobType.Enroll, "k",
            DateTimeOffset.UtcNow.AddHours(1), 31234567, [new JobStep("NotAStepThisAgentKnows")], context);

        var result = await executor.ExecuteAsync(job, null!, 1, CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Equal(["started", "ended:False:NotAStepThisAgentKnows"], window.Log);
        Assert.Same(context, window.Started!.Context);
        Assert.Same(JobSteps.Enrolment, window.Steps);
    }

    [Fact]
    public async Task An_inventory_opens_no_window()
    {
        var window = new RecordingWindow();
        var executor = new JobExecutor(null!, null, null, NullLogger<JobExecutor>.Instance, null, window);
        var job = new JobEnvelope(Protocol.SchemaVersion, Guid.NewGuid(), JobType.Inventory, "k",
            DateTimeOffset.UtcNow.AddHours(1), null, [new JobStep("NotAStepThisAgentKnows")]);

        await executor.ExecuteAsync(job, null!, 1, CancellationToken.None);

        Assert.Empty(window.Log);
    }

    [Fact]
    public void The_context_travels_in_the_envelope_and_an_old_one_reads_without_it()
    {
        var context = new JobContext(JobContext.Passkey, "Jan Kowalski", null, "helpdesk1",
            Provider: "entra", Login: "jan@example.com");
        var job = JobEnvelope.ProvisionFido2(Guid.NewGuid(), "k", DateTimeOffset.UtcNow, null,
            new Fido2Provisioning("entra", "Jan Kowalski",
                new Fido2PinPolicy(Fido2PinMode.OperatorSets, 6, true), "YubiKey", true),
            context);

        var back = JsonSerializer.Deserialize<JobEnvelope>(JsonSerializer.Serialize(job, Json), Json)!;

        Assert.Equal(context, back.Context);

        // Additive: an envelope from a server older than 0084a has no context.
        var old = JsonSerializer.Deserialize<JobEnvelope>(
            """{"schemaVersion":1,"jobId":"00000000-0000-0000-0000-000000000001","type":0,"idempotencyKey":"k","deadlineAt":"2026-10-10T00:00:00Z","tokenSerial":null,"steps":[]}""",
            Json)!;

        Assert.Null(old.Context);
    }

    private sealed class RecordingWindow : IJobWindow
    {
        public List<string> Log { get; } = [];

        public JobEnvelope? Started { get; private set; }

        public IReadOnlyList<string>? Steps { get; private set; }

        public Task JobStartedAsync(JobEnvelope job, IReadOnlyList<string> steps, CancellationToken ct)
        {
            Started = job;
            Steps = steps;
            Log.Add("started");
            return Task.CompletedTask;
        }

        public Task JobStepAsync(string step, CancellationToken ct)
        {
            Log.Add($"step:{step}");
            return Task.CompletedTask;
        }

        public Task JobEndedAsync(bool succeeded, string message, string? failedStep, CancellationToken ct)
        {
            Log.Add($"ended:{succeeded}:{failedStep}");
            return Task.CompletedTask;
        }
    }
}
