using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Blinky.Agent.Service;

/// <summary>
/// Where the agent keeps things, and who is allowed to read them.
/// </summary>
/// <remarks>
/// <para>
/// <c>%ProgramData%</c> is the right place for a service's state: it survives
/// user profiles, it is writable by <c>LocalSystem</c>, and it is where anybody
/// looking for a service's files will look. What it is not is private.
/// </para>
/// <para>
/// A directory created there inherits <c>BUILTIN\Users:(RX)</c>. Measured on
/// this bench rather than assumed:
/// </para>
/// <code>
/// C:\ProgramData\...\agent.key NT AUTHORITY\SYSTEM:(I)(F)
///                              BUILTIN\Administrators:(I)(F)
///                              MACHINE\user:(I)(F)
///                              BUILTIN\Users:(I)(RX)
/// </code>
/// <para>
/// The agent writes its client certificate's private key into that directory.
/// Left inherited, every local user on the workstation could read it and speak
/// to the backend as this machine — an agent identity is not a small thing to
/// hand out, since it is what the API checks before it will discuss a token.
/// </para>
/// <para>
/// So the directories are created with an explicit access list and inheritance
/// switched off, and it is reapplied every time rather than only at creation:
/// a directory that already exists from an older build has the wrong list, and
/// nothing else would ever fix it.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
public static class AgentPaths
{
    /// <summary>Everything the agent keeps, under one root.</summary>
    public static string Root { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Blinky");

    public static string Logs => Path.Combine(Root, "logs");

    /// <summary>
    /// Creates a directory that only the machine and its administrators can
    /// read.
    /// </summary>
    public static string Secure(string path)
    {
        var directory = new DirectoryInfo(path);
        directory.Create();

        var security = new DirectorySecurity();

        // Protected, and inherited rules are not copied across: copying them
        // would keep the Users entry this exists to remove.
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

        var allowed = new List<IdentityReference>
        {
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
        };

        // And whoever is actually running. In production that is LocalSystem
        // and this adds nothing; on a bench it is a developer, and without it
        // the agent would lock itself out of its own identity directory the
        // first time it wrote to it - a hardening step that stops the thing
        // being hardened from working is not one.
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
