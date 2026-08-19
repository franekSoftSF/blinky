namespace Blinky.Contracts;

/// <summary>
/// Job lifecycle. <see cref="AwaitingUser"/> is deliberately distinct: a job
/// blocked on a touch prompt is not stuck, and must not share a deadline with
/// one blocked on a hung APDU.
/// </summary>
public enum JobState
{
    Pending,
    Dispatched,
    Claimed,
    Running,
    AwaitingUser,
    Succeeded,
    Failed,
    Expired,
    Cancelled,
}
