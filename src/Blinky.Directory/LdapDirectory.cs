using System.DirectoryServices.Protocols;
using System.Net;
using Blinky.Domain;

namespace Blinky.Directory;

/// <summary>
/// A directory read over LDAP. Samba4 and Windows AD, on the same wire.
/// </summary>
/// <remarks>
/// <para>
/// Everything this reads — display name, account name, UPN, SID, DN — lives at
/// the same attribute names in both, so one implementation answers both and the
/// configured <see cref="DirectorySource"/> is a label for the record rather
/// than a branch in the code.
/// </para>
/// <para>
/// <b>Read-only, deliberately.</b> Nothing here writes to the directory.
/// Publishing a certificate into <c>userCertificate</c> or touching
/// <c>altSecurityIdentities</c> is a different privilege and a different
/// decision, and a component that only ever reads can be given an account that
/// can only ever read.
/// </para>
/// </remarks>
public sealed class LdapDirectory(LdapDirectoryOptions options) : IDirectory, IDisposable
{
    // Only what is used. An LDAP search that asks for everything makes the
    // server assemble an entry nobody reads, and puts attributes in a log that
    // had no reason to be there.
    private static readonly string[] Attributes =
    [
        "displayName", "cn", "sAMAccountName", "userPrincipalName",
        "objectSid", "distinguishedName", "userAccountControl",
    ];

    private LdapConnection? connection;
    private bool disposed;

    public DirectorySource Source => options.Source;

    public async Task<IReadOnlyList<DirectoryUser>> SearchAsync(string query, int limit = 20,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(query))
        {
            return [];
        }

        var escaped = Escape(query);

        // Prefix rather than substring. A leading wildcard cannot use an index,
        // so `*smith*` over a large directory is a scan the server performs on
        // your behalf and charges everybody else for.
        var filter =
            $"(&(objectCategory=person)(objectClass=user)"
            + $"(|(sAMAccountName={escaped}*)(userPrincipalName={escaped}*)"
            + $"(displayName={escaped}*)(cn={escaped}*)))";

        return await RunAsync(filter, limit, ct);
    }

    public async Task<DirectoryUser?> FindAsync(string upnOrAccount,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(upnOrAccount))
        {
            return null;
        }

        var escaped = Escape(upnOrAccount);

        var filter =
            $"(&(objectCategory=person)(objectClass=user)"
            + $"(|(sAMAccountName={escaped})(userPrincipalName={escaped})))";

        var found = await RunAsync(filter, 2, ct);

        // Two people answering to one name is not something to pick between.
        // It is a directory that needs looking at, and choosing the first would
        // issue a logon credential to whichever one the server happened to
        // return first.
        return found.Count == 1 ? found[0] : null;
    }

    private Task<IReadOnlyList<DirectoryUser>> RunAsync(string filter, int limit,
        CancellationToken ct) =>
        Task.Run<IReadOnlyList<DirectoryUser>>(() =>
        {
            ct.ThrowIfCancellationRequested();

            var request = new SearchRequest(options.BaseDn, filter, SearchScope.Subtree, Attributes);
            request.SizeLimit = limit;

            var response = (SearchResponse)Connect().SendRequest(request);

            var users = new List<DirectoryUser>(response.Entries.Count);

            foreach (SearchResultEntry entry in response.Entries)
            {
                if (Read(entry) is { } user)
                {
                    users.Add(user);
                }
            }

            return users;
        }, ct);

    private static DirectoryUser? Read(SearchResultEntry entry)
    {
        var sid = entry.Attributes["objectSid"]?[0] as byte[];

        // Disabled accounts are returned and marked rather than hidden. An
        // operator searching for somebody who has left should find them and see
        // why they cannot be issued to, not be told they do not exist.
        var control = Text(entry, "userAccountControl");
        var enabled = !int.TryParse(control, out var flags) || (flags & 0x2) == 0;

        var name = Text(entry, "displayName") ?? Text(entry, "cn");

        return name is null ? null : new DirectoryUser(
            name,
            Text(entry, "sAMAccountName"),
            Text(entry, "userPrincipalName"),
            sid is null ? null : SecurityIdentifier.Format(sid),
            entry.DistinguishedName,
            enabled);
    }

    private static string? Text(SearchResultEntry entry, string attribute) =>
        entry.Attributes[attribute]?.Count > 0
            ? entry.Attributes[attribute][0]?.ToString()
            : null;

    /// <summary>
    /// The characters that would otherwise change what the filter means.
    /// </summary>
    /// <remarks>
    /// RFC 4515. Somebody's surname containing a parenthesis is not an attack
    /// and still breaks a filter; somebody typing <c>*)(objectClass=*</c> is,
    /// and this is where both stop.
    /// </remarks>
    private static string Escape(string value) => value
        .Replace("\\", "\\5c")
        .Replace("*", "\\2a")
        .Replace("(", "\\28")
        .Replace(")", "\\29")
        .Replace("\0", "\\00");

    private LdapConnection Connect()
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        if (connection is not null)
        {
            return connection;
        }

        var identifier = new LdapDirectoryIdentifier(options.Host, options.Port,
            fullyQualifiedDnsHostName: true, connectionless: false);

        var ldap = new LdapConnection(identifier)
        {
            AuthType = string.IsNullOrEmpty(options.BindDn) ? AuthType.Negotiate : AuthType.Basic,
        };

        ldap.SessionOptions.ProtocolVersion = 3;

        if (options.UseTls)
        {
            // StartTLS on the plain port rather than LDAPS on 636. Both work;
            // this one is what a Samba4 domain offers without extra setup, and
            // a simple bind must not cross an unencrypted connection.
            ldap.SessionOptions.StartTransportLayerSecurity(null);
        }
        else if (!string.IsNullOrEmpty(options.BindDn))
        {
            throw new InvalidOperationException(
                "A bind DN and password over an unencrypted connection would send the "
                + "password in the clear. Either enable TLS or use Negotiate.");
        }

        if (!string.IsNullOrEmpty(options.BindDn))
        {
            ldap.Bind(new NetworkCredential(options.BindDn, options.BindPassword));
        }
        else
        {
            // Kerberos, from whatever this process holds - a keytab in the
            // container, or a ticket. No password anywhere, which is the
            // arrangement worth having.
            ldap.Bind();
        }

        connection = ldap;
        return connection;
    }

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }

        disposed = true;
        connection?.Dispose();
        connection = null;
    }
}

/// <param name="Source">
/// Which directory this is, for the record on a cardholder. Both speak the same
/// LDAP; this says which one answered.
/// </param>
/// <param name="BindDn">
/// A service account, or empty to bind with Kerberos from this process's own
/// credentials. Empty is better where it is possible.
/// </param>
public sealed record LdapDirectoryOptions(
    string Host,
    int Port,
    string BaseDn,
    DirectorySource Source,
    string? BindDn = null,
    string? BindPassword = null,
    bool UseTls = true);
