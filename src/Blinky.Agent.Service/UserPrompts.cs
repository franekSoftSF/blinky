using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Blinky.Contracts;

namespace Blinky.Agent.Service;

/// <summary>
/// The service's half of the conversation with the user's session.
/// </summary>
/// <remarks>
/// <para>
/// The pipe is granted to <c>INTERACTIVE</c> and to nobody else. That is what
/// makes it a local channel to whoever is actually sitting at the machine: a
/// service account, a scheduled task, or anything arriving over the network is
/// not interactive and cannot connect.
/// </para>
/// <para>
/// If no UI answers, the operation fails. It does not fall back to a
/// configured PIN, because a PIN in configuration is a PIN on disk.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class UserPrompts(ILogger<UserPrompts> logger, TimeSpan timeout,
    string? pipeName = null)
{
    /// <summary>The registered constructor: the timeout comes from configuration.</summary>
    public UserPrompts(ILogger<UserPrompts> logger, AgentOptions options)
        : this(logger, TimeSpan.FromSeconds(options.PromptTimeoutSeconds))
    {
    }

    private readonly string pipeName = pipeName ?? AgentPipe.Name;

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    /// <summary>Asks the user for their PIN. Null means they cancelled or nobody answered.</summary>
    public Task<string?> AskForPinAsync(long serial, int? attemptsRemaining, string reason,
        CancellationToken ct, string? title = null, int? minLength = null, int? maxLength = null,
        string? applet = null) =>
        AskAsync(PromptRequest.ForPin(serial, attemptsRemaining, reason, title, minLength, maxLength, applet), ct);

    /// <summary>
    /// Tells the user the token is waiting for a finger, and returns as soon as
    /// the UI has it on screen — the waiting itself happens in the APDU.
    /// </summary>
    public async Task ShowTouchAsync(long serial, string reason, CancellationToken ct)
    {
        try
        {
            await using var pipe = await ConnectAsync(ct);
            await SendAsync(pipe, PromptRequest.ForTouch(serial, reason), ct);
        }
        catch (Exception ex)
        {
            // Nobody to tell is not a reason to fail the operation: the card
            // blinks whether or not anything explains it.
            logger.LogDebug("No interactive session to show the touch prompt: {Message}",
                ex.Message);
        }
    }

    /// <summary>
    /// Tells the user to present a finger, and returns as soon as the window is
    /// up — the waiting itself happens inside the APDU.
    /// </summary>
    public async Task ShowFingerprintAsync(long serial, int? attemptsRemaining, string reason,
        CancellationToken ct)
    {
        try
        {
            await using var pipe = await ConnectAsync(ct);
            await SendAsync(pipe, PromptRequest.ForFingerprint(serial, attemptsRemaining, reason),
                ct);
        }
        catch (Exception ex)
        {
            // The sensor lights whether or not anything explains it, so this is
            // not a reason to fail the operation - but a lit sensor with no
            // window is a program that looks frozen, so it is worth a line.
            logger.LogWarning("No interactive session to ask for a fingerprint: {Message}",
                ex.Message);
        }
    }

    /// <summary>
    /// Shows something to read and waits until it is closed. The provisional FIDO2
    /// PIN travels this way: over the pipe to the window and nowhere else.
    /// </summary>
    /// <remarks>
    /// Throws when nobody saw it. A PIN that was set on a key and shown to no one
    /// is a key only a reset recovers, and the job must say so rather than succeed.
    /// </remarks>
    /// <param name="wait">
    /// How long to wait for the acknowledgement, when it is not the ordinary
    /// prompt timeout. A provisional PIN is already on the key when it is shown,
    /// so giving up early is the worst outcome at once: a key with a PIN nobody
    /// kept and no passkey on it.
    /// </param>
    public async Task ShowNoticeAsync(long serial, string title, string message, CancellationToken ct,
        string? applet = null, TimeSpan? wait = null)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(wait ?? timeout);

        await using var pipe = await ConnectAsync(deadline.Token);
        await SendAsync(pipe, PromptRequest.ForNotice(serial, title, message, applet), deadline.Token);

        using var reader = new StreamReader(pipe, Encoding.UTF8, false, 1024, leaveOpen: true);

        if (await reader.ReadLineAsync(deadline.Token) is null)
        {
            throw new InvalidOperationException("The window closed before the notice was read.");
        }
    }

    public Task JobStartedAsync(JobEnvelope job, IReadOnlyList<string> steps, CancellationToken ct) =>
        NotifyAsync(PromptRequest.ForJobStarted(job.TokenSerial, job.Context, steps), ct);

    public Task JobStepAsync(string step, CancellationToken ct) =>
        NotifyAsync(PromptRequest.ForJobStep(step), ct);

    public Task JobEndedAsync(bool succeeded, string message, string? failedStep, CancellationToken ct) =>
        NotifyAsync(PromptRequest.ForJobEnded(succeeded, message, failedStep), ct);

    /// <summary>
    /// Sends something the window only needs to know, with a short wait of its
    /// own. Waiting for a connection is otherwise open-ended, and a workstation
    /// where nobody is signed in has no window to connect - an enrolment there
    /// would hang on telling nobody which step it was on.
    /// </summary>
    private async Task NotifyAsync(PromptRequest request, CancellationToken ct)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(NotifyWait);

        try
        {
            await using var pipe = await ConnectAsync(deadline.Token);
            await SendAsync(pipe, request, deadline.Token);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            logger.LogDebug("The window was not told {Type}: {Message}", request.Type, ex.Message);
        }
    }

    private static readonly TimeSpan NotifyWait = TimeSpan.FromSeconds(5);

    /// <summary>Takes the prompt off the screen once the card has answered.</summary>
    public async Task DismissAsync(CancellationToken ct)
    {
        try
        {
            await using var pipe = await ConnectAsync(ct);
            await SendAsync(pipe, PromptRequest.ToDismiss(), ct);
        }
        catch (Exception ex)
        {
            logger.LogDebug("Nothing to dismiss: {Message}", ex.Message);
        }
    }

    private async Task<string?> AskAsync(PromptRequest request, CancellationToken ct)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(timeout);

        try
        {
            await using var pipe = await ConnectAsync(deadline.Token);

            await SendAsync(pipe, request, deadline.Token);

            using var reader = new StreamReader(pipe, Encoding.UTF8, false, 1024, leaveOpen: true);
            var line = await reader.ReadLineAsync(deadline.Token);

            if (line is null)
            {
                return null;
            }

            var response = JsonSerializer.Deserialize<PromptResponse>(line, Json);

            // Never logged, at any level. The one place a PIN exists is the
            // variable it is about to be used from.
            return response is null || response.Cancelled ? null : response.Pin;
        }
        catch (OperationCanceledException)
        {
            logger.LogWarning("Nobody answered the {Type} prompt within {Timeout}",
                request.Type, timeout);

            return null;
        }
        catch (Exception ex)
        {
            logger.LogWarning("The {Type} prompt could not be shown: {Message}",
                request.Type, ex.Message);

            return null;
        }
    }

    private async Task<NamedPipeServerStream> ConnectAsync(CancellationToken ct)
    {
        var security = new PipeSecurity();

        // Whoever is logged in at the console, and nobody else. Not Everyone,
        // not Authenticated Users - both of those include things that are not
        // a person at this keyboard.
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.InteractiveSid, null),
            PipeAccessRights.ReadWrite, AccessControlType.Allow));

        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl, AccessControlType.Allow));

        // More than one instance so a stray listener from a previous attempt
        // cannot block the next prompt with "all pipe instances are busy" -
        // which surfaces as a prompt that never appears.
        var pipe = NamedPipeServerStreamAcl.Create(pipeName, PipeDirection.InOut,
            maxNumberOfServerInstances: 4, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous, inBufferSize: 0, outBufferSize: 0, security);

        await pipe.WaitForConnectionAsync(ct);

        return pipe;
    }

    private static async Task SendAsync(Stream pipe, PromptRequest request, CancellationToken ct)
    {
        var line = JsonSerializer.Serialize(request, Json) + "\n";

        await pipe.WriteAsync(Encoding.UTF8.GetBytes(line), ct);
        await pipe.FlushAsync(ct);
    }
}
