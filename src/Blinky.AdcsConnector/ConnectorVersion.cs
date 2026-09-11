using System.Reflection;

namespace Blinky.AdcsConnector;

/// <summary>
/// What this build calls itself, reported on every describe.
/// </summary>
/// <remarks>
/// The connector is installed on somebody else's server and upgraded by
/// somebody else's change window, so the version is the first thing anybody
/// diagnosing a mismatch will want and the last thing they can obtain by
/// looking at this repository.
/// </remarks>
public static class ConnectorVersion
{
    public static string Value { get; } =
        typeof(ConnectorVersion).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
        ?? "unknown";
}
