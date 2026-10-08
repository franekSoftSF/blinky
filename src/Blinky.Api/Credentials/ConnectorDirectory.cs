using System.Diagnostics;
using Blinky.Contracts;
using Blinky.Directory;
using Blinky.Domain;
using Blinky.Pki;
using Blinky.Pki.Adcs;

namespace Blinky.Api.Credentials;

/// <summary>
/// Active Directory, read by the ADCS connector as the domain account it runs as,
/// instead of by this API with a bind DN and a password in <c>.env</c> (0104).
/// </summary>
/// <remarks>
/// <para>
/// Chosen with <c>Blinky:Directory:Via=Connector</c>. The connector already is the
/// integration account on a domain member: it reads templates as it, it asks the CA as
/// it, and with this it reads the people the CA issues for as it - through Kerberos,
/// with no password stored on either side. The Linux host that runs this API holds no
/// credential for the domain at all.
/// </para>
/// <para>
/// Every answer is what a direct bind would give: the connector runs the same
/// <see cref="LdapDirectory"/>. A connector that cannot be reached fails a read the way
/// an unreachable domain controller does, and a probe reports it rather than throwing.
/// </para>
/// </remarks>
public sealed class ConnectorDirectory(ConnectorAdcsTransport connector, string? netBiosDomain = null)
    : IDirectory
{
    public DirectorySource Source => DirectorySource.ActiveDirectory;

    /// <summary>The domain controller the connector last said it read, for the status page.</summary>
    public string? Host { get; private set; }

    /// <summary>The naming context the connector last said it searched.</summary>
    public string? BaseDn { get; private set; }

    public async Task<IReadOnlyList<DirectoryUser>> SearchAsync(string query, int limit = 20,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(query))
        {
            return [];
        }

        var found = await connector.DirectoryAsync<ConnectorDirectoryUsers>(
            ConnectorDirectoryPaths.Search, new ConnectorDirectoryRequest(query, limit), ct);

        return found.Users.Select(Read).ToList();
    }

    public async Task<DirectoryUser?> FindAsync(string upnOrAccount, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(upnOrAccount))
        {
            return null;
        }

        var found = await connector.DirectoryAsync<ConnectorDirectoryFound>(
            ConnectorDirectoryPaths.Find, new ConnectorDirectoryRequest(upnOrAccount), ct);

        return found.User is { } user ? Read(user) : null;
    }

    public async Task<DirectoryProbe> TestAsync(CancellationToken ct = default)
    {
        var started = Stopwatch.StartNew();

        try
        {
            var probe = await connector.DirectoryAsync<ConnectorDirectoryProbe>(
                ConnectorDirectoryPaths.Probe, new ConnectorDirectoryRequest(string.Empty), ct);

            Host = probe.Host ?? Host;
            BaseDn = probe.BaseDn ?? BaseDn;

            return new DirectoryProbe(probe.Reachable, probe.BaseDnFound, probe.BoundAs,
                probe.Encrypted, probe.Milliseconds, $"Through the connector: {probe.Detail}");
        }
        catch (CertificateAuthorityException ex)
        {
            return new DirectoryProbe(false, false, null, true, (int)started.ElapsedMilliseconds,
                ex.Message);
        }
    }

    public async Task<IReadOnlyList<DirectoryUser>> MembersOfAsync(string group, int limit = 200,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(group))
        {
            return [];
        }

        var found = await connector.DirectoryAsync<ConnectorDirectoryUsers>(
            ConnectorDirectoryPaths.Members, new ConnectorDirectoryRequest(group, limit), ct);

        return found.Users.Select(Read).ToList();
    }

    public async Task<DirectoryWriteAccess> CanWriteAsync(string subjectDn, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(subjectDn))
        {
            return DirectoryWriteAccess.Unknown(
                "Permissions are per object, so this needs somebody to ask about.");
        }

        try
        {
            var access = await connector.DirectoryAsync<ConnectorDirectoryWriteAccess>(
                ConnectorDirectoryPaths.WriteAccess, new ConnectorDirectoryRequest(subjectDn), ct);

            return new DirectoryWriteAccess(
                access.Determined, access.UserCertificate, access.AltSecurityIdentities, access.Detail);
        }
        catch (CertificateAuthorityException ex)
        {
            return DirectoryWriteAccess.Unknown(
                $"Effective permissions could not be read through the connector: {ex.Message}");
        }
    }

    public async Task<string?> NetBiosDomainAsync(string distinguishedName, CancellationToken ct = default)
    {
        // Configured here wins without a round trip, as it does for a direct bind.
        if (netBiosDomain is { Length: > 0 } configured)
        {
            return configured;
        }

        if (string.IsNullOrWhiteSpace(distinguishedName))
        {
            return null;
        }

        var answer = await connector.DirectoryAsync<ConnectorDirectoryNetBios>(
            ConnectorDirectoryPaths.NetBios, new ConnectorDirectoryRequest(distinguishedName), ct);

        return answer.Name;
    }

    private static DirectoryUser Read(ConnectorDirectoryUser user) =>
        new(user.DisplayName, user.SamAccountName, user.Upn, user.ObjectSid,
            user.DistinguishedName, user.Enabled);
}
