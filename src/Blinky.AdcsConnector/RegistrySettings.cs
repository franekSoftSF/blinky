using Microsoft.Win32;

namespace Blinky.AdcsConnector;

/// <summary>
/// What the MSI was told, read from <c>HKLM\SOFTWARE\Blinky\AdcsConnector</c> (0105).
/// </summary>
/// <remarks>
/// The registry rather than a JSON file written by the installer, as the agent does:
/// MSI writes registry values natively and a domain can change them by policy without
/// repackaging. Read under <c>connector.json</c>, so a file somebody wrote by hand still
/// wins over what the installer was given.
/// </remarks>
public static class RegistrySettings
{
    private static readonly (string Value, string Setting)[] Map =
    [
        ("ApiUrl", "Connector:Api:Url"),
        ("ApiServerFingerprint", "Connector:Api:ServerFingerprint"),
        ("CaConfig", "Connector:CaConfig"),
        ("DirectoryEnabled", "Connector:Directory:Enabled"),

        // Written by Install-BlinkyConnector.ps1 once it has found or requested the
        // enrolment agent certificate, which the MSI cannot know about.
        ("EnrolmentAgentThumbprint", "Connector:EnrolmentAgent:Thumbprint"),
        ("EnrolmentAgentStore", "Connector:EnrolmentAgent:StoreLocation"),
    ];

    public static IEnumerable<KeyValuePair<string, string?>> Read()
    {
        using var key = Registry.LocalMachine.OpenSubKey(ConnectorIdentity.RegistryKey);

        if (key is null)
        {
            yield break;
        }

        foreach (var (value, setting) in Map)
        {
            if (key.GetValue(value) is string { Length: > 0 } text)
            {
                yield return new(setting, text.Trim());
            }
        }
    }
}
