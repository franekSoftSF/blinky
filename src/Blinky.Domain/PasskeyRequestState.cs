namespace Blinky.Domain;

/// <summary>
/// A request for a passkey made at a workstation, waiting for an operator.
/// </summary>
/// <remarks>
/// Three states and no way back. A rejected request asked again is a new row:
/// who asked, who said no and why are part of that key's history, and a second
/// attempt that overwrote the first would hide the refusal from the next
/// operator to look.
/// </remarks>
public enum PasskeyRequestState
{
    /// <summary>Asked for at the workstation; nobody has decided.</summary>
    Pending,

    /// <summary>An operator said yes, and the job exists.</summary>
    Approved,

    /// <summary>An operator said no, with a reason.</summary>
    Rejected,
}
