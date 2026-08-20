namespace Blinky.Contracts;

/// <summary>
/// What the service in session 0 asks the user's session to show, and what
/// comes back.
/// </summary>
/// <remarks>
/// <para>
/// The service runs as LocalSystem and cannot draw a window; the UI runs as the
/// user and cannot hold the reader. That is the whole reason there are two
/// processes, and this is the only thing that crosses between them.
/// </para>
/// <para>
/// <b>A PIN travels over this pipe and stops there.</b> It is used for one
/// command and cleared. It is never written to a job payload, never logged,
/// never stored — see docs/02-data-model.md.
/// </para>
/// </remarks>
public static class AgentPipe
{
    /// <summary>
    /// One pipe, reachable only from an interactive session on this machine.
    /// </summary>
    public const string Name = "Blinky.Agent.Prompts";
}

/// <summary>Something the service wants the user to see.</summary>
public sealed record PromptRequest(
    string Type,
    string Title,
    string Message,
    long? TokenSerial = null,
    int? AttemptsRemaining = null)
{
    public const string Pin = "Pin";
    public const string Touch = "Touch";
    public const string Dismiss = "Dismiss";

    public static PromptRequest ForPin(long serial, int? attemptsRemaining, string reason) =>
        new(Pin, "Blinky needs your PIN",
            reason, serial, attemptsRemaining);

    /// <summary>
    /// A token with a touch policy blinks and waits. Nothing is typed here —
    /// the prompt exists so the blinking is explained rather than mysterious.
    /// </summary>
    public static PromptRequest ForTouch(long serial, string reason) =>
        new(Touch, "Touch your key", reason, serial);

    public static PromptRequest ToDismiss() =>
        new(Dismiss, string.Empty, string.Empty);
}

/// <summary>What the user did.</summary>
/// <param name="Pin">
/// Present only for a PIN prompt, and only on the way from the UI to the
/// service. Nothing downstream keeps it.
/// </param>
public sealed record PromptResponse(bool Cancelled, string? Pin = null)
{
    public static PromptResponse Cancel() => new(true);

    public static PromptResponse WithPin(string pin) => new(false, pin);
}
