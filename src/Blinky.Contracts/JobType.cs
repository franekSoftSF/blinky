namespace Blinky.Contracts;

/// <summary>Kinds of work the server hands to an agent. See docs/02-data-model.md.</summary>
public enum JobType
{
    Inventory,
    Enroll,
    Renew,
    Revoke,
    UnblockPin,
    RotateMgmtKey,
    ResetCard,
}
