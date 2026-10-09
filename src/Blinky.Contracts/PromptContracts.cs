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
/// <param name="MinLength">
/// How long the PIN asked for may be. Absent means a PIV PIN, six to eight -
/// which is what a window older than these fields assumes. A FIDO2 PIN is four
/// to 63, and the window refusing the ninth character locked out every holder
/// whose FIDO2 PIN was longer than their smart card's.
/// </param>
public sealed record PromptRequest(
    string Type,
    string Title,
    string Message,
    long? TokenSerial = null,
    int? AttemptsRemaining = null,
    int? MinLength = null,
    int? MaxLength = null,
    string? Applet = null)
{
    /// <summary>
    /// Which PIN is asked for. Absent means PIV, as everything before this field
    /// did. FIDO2 changes the window's words, not its behaviour: there is nothing
    /// to unlock, so the button says Continue, and a provisional PIN's notice
    /// waits for "I have written it down" rather than a Close anybody can click
    /// past - a holder who did not keep it was asked for it at the next attempt
    /// and had nothing to type.
    /// </summary>
    public const string Piv = "Piv";

    public const string Fido2 = "Fido2";

    public const string Pin = "Pin";
    public const string Touch = "Touch";
    public const string Fingerprint = "Fingerprint";
    public const string Dismiss = "Dismiss";

    /// <summary>
    /// Something to read and acknowledge - a provisional FIDO2 PIN, shown once.
    /// A window that does not know this type already does the right thing with
    /// it: shows the title and the message with a Close button, and answers when
    /// it is closed.
    /// </summary>
    public const string Notice = "Notice";

    /// <param name="title">
    /// Overrides the heading. Worth having because two PIN prompts in a row -
    /// choosing one and confirming it - are the same window with the same
    /// heading, and a person reading the heading sees the first prompt twice.
    /// The message underneath is not where anybody looks to find out what is
    /// being asked.
    /// </param>
    public static PromptRequest ForPin(long serial, int? attemptsRemaining, string reason,
        string? title = null, int? minLength = null, int? maxLength = null, string? applet = null) =>
        new(Pin, title ?? "Blinky needs your PIN",
            reason, serial, attemptsRemaining, minLength, maxLength, applet);

    /// <summary>
    /// A token with a touch policy blinks and waits. Nothing is typed here —
    /// the prompt exists so the blinking is explained rather than mysterious.
    /// </summary>
    public static PromptRequest ForTouch(long serial, string reason) =>
        new(Touch, "Touch your key", reason, serial);

    /// <summary>
    /// A Bio waiting for a finger.
    /// </summary>
    /// <remarks>
    /// Distinct from <see cref="ForTouch"/>, which they resemble to a watchdog
    /// and not at all to a person: one asks for contact with a metal disc, the
    /// other for a fingerprint that can fail and that has three attempts behind
    /// it. The count travels so the window can say what is left.
    /// </remarks>
    public static PromptRequest ForFingerprint(long serial, int? attemptsRemaining,
        string reason) =>
        new(Fingerprint, "Blinky needs your fingerprint", reason, serial, attemptsRemaining);

    public static PromptRequest ForNotice(long serial, string title, string message, string? applet = null) =>
        new(Notice, title, message, serial, Applet: applet);

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
