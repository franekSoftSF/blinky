namespace Blinky.Contracts;

/// <summary>
/// Wire protocol version carried by every job envelope. Additive changes do not
/// bump it; removals and semantic changes do. See docs/05-agent-protocol.md.
/// </summary>
/// <remarks>
/// A message carries the lowest version that can read it, not the highest this
/// build speaks. Version 2 exists for one job type; stamping it on every envelope
/// would have turned a FIDO2 feature into every deployed agent refusing its
/// inventory and its PIV enrolments until somebody upgraded it.
/// </remarks>
public static class Protocol
{
    /// <summary>The version of every message that has not changed since the first.</summary>
    public const int SchemaVersion = 1;

    /// <summary>
    /// <see cref="JobType.ProvisionFido2Credential"/> and its messages. Bumped
    /// rather than added quietly: an agent from before 0074 knows neither the job
    /// type nor the step, and must say "protocol 2, I speak 1" instead of
    /// finding out halfway through.
    /// </summary>
    public const int Fido2SchemaVersion = 2;

    /// <summary>Envelope versions this build understands, inclusive.</summary>
    public const int MinimumSupportedVersion = 1;

    public const int MaximumSupportedVersion = 2;

    public static bool IsSupported(int schemaVersion) =>
        schemaVersion >= MinimumSupportedVersion && schemaVersion <= MaximumSupportedVersion;

    /// <summary>The version an envelope of this type carries.</summary>
    public static int VersionFor(JobType type) =>
        type is JobType.ProvisionFido2Credential ? Fido2SchemaVersion : SchemaVersion;
}
