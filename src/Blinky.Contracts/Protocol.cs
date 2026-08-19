namespace Blinky.Contracts;

/// <summary>
/// Wire protocol version carried by every job envelope. Additive changes do not
/// bump it; removals and semantic changes do. See docs/05-agent-protocol.md.
/// </summary>
public static class Protocol
{
    public const int SchemaVersion = 1;

    /// <summary>Envelope versions this build understands, inclusive.</summary>
    public const int MinimumSupportedVersion = 1;

    public const int MaximumSupportedVersion = 1;

    public static bool IsSupported(int schemaVersion) =>
        schemaVersion >= MinimumSupportedVersion && schemaVersion <= MaximumSupportedVersion;
}
