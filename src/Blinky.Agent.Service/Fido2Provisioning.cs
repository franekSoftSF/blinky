using System.Net.Http.Json;
using System.Runtime.Versioning;
using System.Text.Json;
using Blinky.Contracts;
using Blinky.Fido;

namespace Blinky.Agent.Service;

/// <summary>Runs the <c>ProvisionFido2Credential</c> step.</summary>
public interface IFido2Step
{
    Task RunAsync(JobEnvelope job, JobStep step, BackendClient backend, int attempt, CancellationToken ct);
}

/// <summary>
/// The FIDO2 step: open the key, hand it to the engine, and say how it ended.
/// </summary>
/// <remarks>
/// Windows-only like every other card operation here - the prompts end in a user
/// session - and LocalSystem by necessity: Windows opens the FIDO HID interface to
/// elevated processes only, which the tray is not.
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class Fido2Step(UserPrompts prompts, ILogger<Fido2Step> logger, Func<long?, IFidoKey>? open = null)
    : IFido2Step
{
    private readonly Func<long?, IFidoKey> openKey = open ?? Blinky.Fido.Yubico.YubicoFidoKeys.Open;

    public async Task RunAsync(JobEnvelope job, JobStep step, BackendClient backend, int attempt, CancellationToken ct)
    {
        var provisioning = Fido2Provisioning.FromStep(step);

        await prompts.JobStepAsync(Fido2Steps.OpenKey, ct);

        using var key = openKey(job.TokenSerial);
        var serial = key.Info().Serial ?? 0;

        var engine = new Fido2Provisioner(new WindowPrompts(prompts, serial, provisioning.Holder,
                (state, detail) => ReportAsync(backend, job, attempt, state, detail, ct)),
            new Fido2BackendCalls(backend), TimeProvider.System);

        try
        {
            var outcome = await engine.RunAsync(key, job.JobId, attempt, job.TokenSerial, provisioning, ct);

            foreach (var warning in outcome.Warnings)
            {
                logger.LogWarning("Job {JobId}: {Warning}", job.JobId, warning);
            }

            if (!outcome.Registered)
            {
                throw new InvalidOperationException(outcome.Warnings.LastOrDefault() ?? "The provider refused the passkey.");
            }

            logger.LogInformation("Job {JobId}: passkey {MethodId} registered on key {Serial} as '{Name}'; "
                                  + "PIN set by agent: {PinSet}, forced change: {Forced}",
                job.JobId, outcome.MethodId, outcome.TokenSerial, outcome.KeyName, outcome.PinSetByAgent,
                outcome.ForcedPinChange);
        }
        finally
        {
            await prompts.DismissAsync(ct);
        }
    }

    /// <summary>
    /// The agent's window, saying FIDO2 every time. A person who has a PIV PIN
    /// for logon and is asked for "your PIN" types that one, burns a FIDO2 retry,
    /// and nothing on screen tells them why it was wrong.
    /// </summary>
    /// <summary>
    /// Progress that must not fail the job. The PIN may already be on the key
    /// when this is called, and a refused progress report is no reason to
    /// abandon a ceremony the person is in the middle of.
    /// </summary>
    private async Task ReportAsync(BackendClient backend, JobEnvelope job, int attempt, JobState state,
        string detail, CancellationToken ct)
    {
        try
        {
            await backend.ReportProgressAsync(new JobProgress(job.JobId, attempt, state, "ProvisionalPin", detail), ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning("Job {JobId}: progress '{Detail}' not reported: {Message}", job.JobId, detail, ex.Message);
        }
    }

    private sealed class WindowPrompts(UserPrompts prompts, long serial, string holder,
        Func<JobState, string, Task> report) : IFido2Prompts
    {
        /// <summary>
        /// As long as the API's AwaitingUser lease (JobService.AwaitingUserLease),
        /// so neither side gives up on a person who is still writing the PIN down.
        /// </summary>
        private static readonly TimeSpan NoticeWait = TimeSpan.FromMinutes(30);

        private const string Title = "Security key PIN (FIDO2)";
        private const string NotPiv = "This is the security key's FIDO2 PIN, not the smart card PIN used to sign in to Windows.";

        // Said on the current-PIN prompt because of what happened on PC-0001 with
        // Okta on 2026-10-09: Blinky set a provisional PIN, showed it once, the
        // provider refused the factor and the job failed - and the next attempt
        // asked the holder for a "current PIN" they had no reason to know.
        private const string MaybeOurs =
            "If an earlier attempt by Blinky failed, the PIN may be the one it showed then. "
            + "Without it, the key's FIDO2 part has to be reset, which removes its passkeys "
            + "and leaves the smart card (PIV) untouched.";

        public Task<string?> AskCurrentPinAsync(int? retries, bool wrong, CancellationToken ct) =>
            prompts.AskForPinAsync(serial, retries,
                (wrong ? "That FIDO2 PIN was wrong. " : "") + $"Enter the key's current FIDO2 PIN. {NotPiv} {MaybeOurs}",
                ct, Title, 4, 63, PromptRequest.Fido2);

        public Task<string?> AskNewPinAsync(int minLength, bool rejected, CancellationToken ct) =>
            prompts.AskForPinAsync(serial, null,
                (rejected ? "The key did not accept that PIN. " : "")
                + $"Choose a FIDO2 PIN for {Holder}, at least {minLength} characters. {NotPiv}", ct, "Choose a FIDO2 PIN",
                minLength, 63, PromptRequest.Fido2);

        public async Task ShowProvisionalPinAsync(string pin, CancellationToken ct)
        {
            // AwaitingUser first: the ordinary lease is five minutes, and the
            // watchdog would take the job back from somebody still holding a pen.
            // The challenge is not fetched yet - the PIN is set before Ready - so
            // no provider deadline runs while this window waits.
            await report(JobState.AwaitingUser, "waiting for the provisional FIDO2 PIN to be written down");

            await prompts.ShowNoticeAsync(serial, "Write down this FIDO2 PIN",
                $"The FIDO2 PIN for {Holder}'s key is {pin}\n\nIt is shown once and stored nowhere. "
                + "Give it to the holder with the key; they will be asked to change it the first time they use it.", ct,
                PromptRequest.Fido2, NoticeWait);

            await report(JobState.Running, "provisional FIDO2 PIN acknowledged");
        }

        public async Task TouchAsync(CancellationToken ct)
        {
            await prompts.JobStepAsync(Fido2Steps.Touch, ct);
            await prompts.ShowTouchAsync(serial, $"Touch the key to create the passkey for {Holder}.", ct);
        }

        public Task StatusAsync(string message, CancellationToken ct) => Task.CompletedTask;

        public Task StepAsync(string step, CancellationToken ct) => prompts.JobStepAsync(step, ct);

        private string Holder => string.IsNullOrWhiteSpace(holder) ? "the holder" : holder;
    }
}

/// <summary>The two FIDO2 calls, with the API's refusal code kept.</summary>
public sealed class Fido2BackendCalls(BackendClient backend) : IFido2Backend
{
    public Task<Fido2CeremonyRequest> ReadyAsync(Fido2Ready ready, CancellationToken ct) =>
        backend.PostFido2Async<Fido2Ready, Fido2CeremonyRequest>($"/api/jobs/{ready.JobId}/fido2/ready", ready, ct);

    public Task<Fido2Registered> ResultAsync(Fido2CeremonyResult result, CancellationToken ct) =>
        backend.PostFido2Async<Fido2CeremonyResult, Fido2Registered>($"/api/jobs/{result.JobId}/fido2/result", result, ct);
}

/// <summary>The API refused a FIDO2 call, with the code it gave.</summary>
public sealed class Fido2RefusedException(int status, string? code, string message) : Exception(message)
{
    public int Status { get; } = status;

    public string? Code { get; } = code;
}

public sealed partial class BackendClient
{
    internal async Task<TResponse> PostFido2Async<TRequest, TResponse>(string path, TRequest body, CancellationToken ct)
    {
        var response = await Authenticated().PostAsJsonAsync(path, body, ct);

        if (!response.IsSuccessStatusCode)
        {
            var text = await response.Content.ReadAsStringAsync(ct);
            string? code = null, error = null;

            try
            {
                using var doc = JsonDocument.Parse(text);
                code = doc.RootElement.TryGetProperty("code", out var c) ? c.GetString() : null;
                error = doc.RootElement.TryGetProperty("error", out var e) ? e.GetString() : null;
            }
            catch (JsonException)
            {
            }

            throw new Fido2RefusedException((int)response.StatusCode, code,
                $"The API refused {path}: {(int)response.StatusCode} {error ?? text}");
        }

        return await response.Content.ReadFromJsonAsync<TResponse>(ct)
               ?? throw new InvalidOperationException($"{path} answered with nothing.");
    }
}
