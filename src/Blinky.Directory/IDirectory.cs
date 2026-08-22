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
}
