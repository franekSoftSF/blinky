namespace Blinky.Domain;

/// <summary>Token lifecycle. See docs/02-data-model.md.</summary>
public enum TokenState
{
    Detected,
    Registered,
    Personalised,
    Assigned,
    Active,
    Suspended,
    Lost,
    Stolen,
    Terminated,
    Retired,
    Rejected,
}
