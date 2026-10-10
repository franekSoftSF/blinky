using System.Runtime.Versioning;
using Blinky.Contracts;

namespace Blinky.Agent.Service;

/// <summary>
/// The issuance window in the user's session: told when a job starts, which
/// step it is on, and how it ended (0084a).
/// </summary>
/// <remarks>
/// Telling, never asking. None of these waits for a person, and none of them
/// can fail a job: a workstation with nobody signed in still enrols a card an
/// operator sent, and a window that did not open is a worse experience, not a
/// failed credential.
/// </remarks>
public interface IJobWindow
{
    Task JobStartedAsync(JobEnvelope job, IReadOnlyList<string> steps, CancellationToken ct);

    Task JobStepAsync(string step, CancellationToken ct);

    Task JobEndedAsync(bool succeeded, string message, string? failedStep, CancellationToken ct);
}

/// <summary>The window, told over the prompt pipe.</summary>
[SupportedOSPlatform("windows")]
public sealed class PipeJobWindow(UserPrompts prompts) : IJobWindow
{
    public Task JobStartedAsync(JobEnvelope job, IReadOnlyList<string> steps, CancellationToken ct) =>
        prompts.JobStartedAsync(job, steps, ct);

    public Task JobStepAsync(string step, CancellationToken ct) => prompts.JobStepAsync(step, ct);

    public Task JobEndedAsync(bool succeeded, string message, string? failedStep, CancellationToken ct) =>
        prompts.JobEndedAsync(succeeded, message, failedStep, ct);
}
