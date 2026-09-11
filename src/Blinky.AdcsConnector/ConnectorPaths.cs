using System.Security.AccessControl;
using System.Security.Principal;

namespace Blinky.AdcsConnector;

/// <summary>
/// Where the connector keeps things, and who is allowed to read them.
/// </summary>
/// <remarks>
/// <para>
/// The same reasoning as <c>AgentPaths</c>, one difference: the agent runs as
/// <c>LocalSystem</c> and this does not. A connector running as
/// <c>LocalSystem</c> would enrol against ADCS as the CA machine account, which
/// is not an identity anybody can grant *Enroll* to on a template in a way that
/// means what they intended. It runs as a domain service account, so the
/// account itself has to appear in the list - inherited rights are exactly what
/// is being removed here.
/// </para>
/// </remarks>
public static class ConnectorPaths
{
    public static string Root { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Blinky",
        "AdcsConnector");

    public static string Logs => Path.Combine(Root, "logs");

    public static string Secure(string path)
    {
        var directory = new DirectoryInfo(path);
        directory.Create();

        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

        var allowed = new List<IdentityReference>
        {
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
        };

        if (WindowsIdentity.GetCurrent().User is { } self && !allowed.Contains(self))
        {
            allowed.Add(self);
        }

        foreach (var identity in allowed)
        {
            security.AddAccessRule(new FileSystemAccessRule(
                identity,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
        }

        directory.SetAccessControl(security);

        return directory.FullName;
    }
}
