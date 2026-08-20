using System.Runtime.Versioning;
using Microsoft.Extensions.Configuration;
using Microsoft.Win32;

namespace Blinky.Agent.Service;

/// <summary>
/// Agent settings from <c>HKLM\SOFTWARE\Blinky\Agent</c>.
/// </summary>
/// <remarks>
/// <para>
/// Where a Windows service's settings belong. The installer writes them
/// natively — no custom action rendering JSON — and a domain can push the same
/// values by policy afterwards without repackaging anything, which is how a
/// fleet actually gets configured.
/// </para>
/// <para>
/// The key is created by the installer with <c>SYSTEM</c> and
/// <c>Administrators</c> only, because one of these values is the bootstrap
/// token. `HKLM\SOFTWARE` is world-readable by default, and a token every user
/// can read is a token that buys an agent certificate for anybody who asks.
/// </para>
/// <para>
/// Values are strings named after the settings they carry — <c>BackendUrl</c>,
/// <c>Domain</c>, <c>BootstrapToken</c> — and land under <c>Agent:</c>, so
/// anything the class already reads works here with no extra mapping.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class RegistryConfigurationSource : IConfigurationSource
{
    public const string KeyPath = @"SOFTWARE\Blinky\Agent";

    public IConfigurationProvider Build(IConfigurationBuilder builder) =>
        new RegistryConfigurationProvider();
}

/// <inheritdoc cref="RegistryConfigurationSource"/>
[SupportedOSPlatform("windows")]
public sealed class RegistryConfigurationProvider : ConfigurationProvider
{
    public override void Load()
    {
        // Missing is the normal state on a machine installed any other way, and
        // is not worth a word. A key that exists and cannot be read is worth
        // one, but the agent has no logger this early - it surfaces as the
        // setting simply being absent, which the startup checks already report
        // properly.
        using var key = Registry.LocalMachine.OpenSubKey(RegistryConfigurationSource.KeyPath);

        if (key is null)
        {
            return;
        }

        foreach (var name in key.GetValueNames())
        {
            if (key.GetValue(name) is { } value)
            {
                Data[$"Agent:{name}"] = value.ToString();
            }
        }
    }
}
