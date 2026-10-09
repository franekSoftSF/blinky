namespace Blinky.Contracts;

/// <summary>
/// A workstation's request for a passkey, as the agent and the tray see it
/// (0109).
/// </summary>
/// <remarks>
/// <para>
/// Carried from the API to the service, and from the service over the request
/// pipe to the tray, unchanged. Nothing in it is secret: a serial, a state, and
/// an operator's reason for saying no.
/// </para>
/// <para>
/// <paramref name="State"/> is the name of <c>PasskeyRequestState</c> -
/// <c>Pending</c>, <c>Approved</c>, <c>Rejected</c> - as text, so a tray older
/// than a fourth state shows the word rather than misreading a number.
/// </para>
/// </remarks>
public sealed record PasskeyRequestView(
    Guid Id,
    long TokenSerial,
    string State,
    string? RejectionReason,
    DateTime CreatedAt,
    DateTime? DecidedAt)
{
    public const string Pending = "Pending";
    public const string Approved = "Approved";
    public const string Rejected = "Rejected";
}
