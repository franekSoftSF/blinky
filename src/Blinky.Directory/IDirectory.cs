using Blinky.Domain;

namespace Blinky.Directory;

/// <summary>
/// Where the people come from.
/// </summary>
/// <remarks>
/// <para>
/// A <c>smartcard-logon</c> certificate is refused without a resolved
/// <c>objectSid</c>, and that refusal is right: since KB5014754 a domain
/// controller ignores a certificate mapped by name alone. So the SID has to be
/// read from the directory that will later be asked to honour it — not typed
/// by an operator, who can only produce a plausible one.
/// </para>
/// <para>
/// One interface, two directories, and for everything read here they are the
/// same wire: Samba4 and Windows AD answer the same LDAP with the same
/// attributes. A Windows-native connector earns its place where LDAP falls
/// short, not because the directory runs on Windows.
/// </para>
/// </remarks>
public interface IDirectory
{
    /// <summary>Which kind of directory this speaks to, for the record.</summary>
    DirectorySource Source { get; }

    /// <summary>
    /// Finds people by name, account name or UPN.
    /// </summary>
    /// <param name="query">
    /// What somebody typed. Matched as a prefix rather than anywhere in the
    /// string: a substring search over a large directory is a table scan the
    /// server performs for you.
    /// </param>
    Task<IReadOnlyList<DirectoryUser>> SearchAsync(string query, int limit = 20,
        CancellationToken ct = default);

    /// <summary>
    /// Reads one person exactly, by UPN or account name.
    /// </summary>
    /// <returns>Null when there is no such person, which is not an error.</returns>
    Task<DirectoryUser?> FindAsync(string upnOrAccount, CancellationToken ct = default);

    /// <summary>
    /// Binds and reports what happened, without reading anybody.
    /// </summary>
    /// <remarks>
    /// For the button in the settings page. "It does not work" is not a useful
    /// answer to somebody who has just typed six fields, so this says which of
    /// them was wrong: the host was not reachable, the bind was refused, the
    /// base was not there.
    /// </remarks>
    Task<DirectoryProbe> TestAsync(CancellationToken ct = default);

    /// <summary>
    /// Everyone in a group, so a rollout can be tried against a real set of
    /// people before anybody is issued to.
    /// </summary>
    Task<IReadOnlyList<DirectoryUser>> MembersOfAsync(string group, int limit = 200,
        CancellationToken ct = default);

    /// <summary>
    /// Whether the account this binds as could write the attributes that
    /// patch 0035 would need.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Asked, never attempted.</b> Active Directory computes
    /// <c>allowedAttributesEffective</c> per object for the bound principal —
    /// which is exactly this question, answered by the directory itself. The
    /// alternative, writing something to see whether it sticks, is a change
    /// nobody asked for made to a real person's account in order to find out
    /// something.
    /// </para>
    /// <para>
    /// A directory that does not compute the attribute gets
    /// <see cref="DirectoryWriteAccess.Unknown"/> rather than a guess. Not
    /// every server offers it, and "we could not tell" is a true answer where
    /// "no" would be a false one.
    /// </para>
    /// </remarks>
    /// <param name="subjectDn">
    /// The object to ask about. Permissions in a directory are per object, so
    /// there is no answer to the question in general — only about somebody.
    /// </param>
    Task<DirectoryWriteAccess> CanWriteAsync(string subjectDn, CancellationToken ct = default);
}

/// <summary>What a connection test found.</summary>
/// <param name="Detail">
/// What to tell the person who pressed the button. Names the field that was
/// wrong where that can be worked out.
/// </param>
public sealed record DirectoryProbe(
    bool Reachable,
    bool BaseDnFound,
    string? BoundAs,
    bool Encrypted,
    int Milliseconds,
    string Detail)
{
    public bool Succeeded => Reachable && BaseDnFound;
}

/// <summary>
/// Whether the bound account may write the two attributes 0035 would use.
/// </summary>
/// <param name="Determined">
/// False when the directory does not compute effective permissions. Neither
/// yes nor no, and said as such.
/// </param>
public sealed record DirectoryWriteAccess(
    bool Determined,
    bool UserCertificate,
    bool AltSecurityIdentities,
    string Detail)
{
    public static DirectoryWriteAccess Unknown(string why) => new(false, false, false, why);

    /// <summary>What the account can do beyond reading, if anything.</summary>
    public bool AnythingExtra => Determined && (UserCertificate || AltSecurityIdentities);
}

/// <summary>
/// A person, as the directory holds them.
/// </summary>
/// <param name="ObjectSid">
/// The security identifier, in the <c>S-1-5-21-…</c> form. This is the field
/// that makes a logon certificate work, and the reason this interface exists.
/// </param>
public sealed record DirectoryUser(
    string DisplayName,
    string? SamAccountName,
    string? Upn,
    string? ObjectSid,
    string? DistinguishedName,
    bool Enabled);

/// <summary>Nothing to ask. Configured with no directory, and honest about it.</summary>
/// <remarks>
/// Registered rather than leaving the dependency absent, so the endpoints exist
/// and answer "there is no directory here" instead of failing to resolve a
/// service. A deployment without one is a normal deployment: cardholders are
/// entered by hand and <c>DirectorySource.Local</c> says so.
/// </remarks>
public sealed class NoDirectory : IDirectory
{
    public DirectorySource Source => DirectorySource.Local;

    public Task<IReadOnlyList<DirectoryUser>> SearchAsync(string query, int limit = 20,
        CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<DirectoryUser>>([]);

    public Task<DirectoryUser?> FindAsync(string upnOrAccount, CancellationToken ct = default) =>
        Task.FromResult<DirectoryUser?>(null);

    public Task<DirectoryProbe> TestAsync(CancellationToken ct = default) =>
        Task.FromResult(new DirectoryProbe(false, false, null, false, 0,
            "No directory is configured. Set Blinky:Directory:Host and BaseDn."));

    public Task<IReadOnlyList<DirectoryUser>> MembersOfAsync(string group, int limit = 200,
        CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<DirectoryUser>>([]);

    public Task<DirectoryWriteAccess> CanWriteAsync(string subjectDn,
        CancellationToken ct = default) =>
        Task.FromResult(DirectoryWriteAccess.Unknown("No directory is configured."));
}
