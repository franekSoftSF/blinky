using Blinky.Directory;
using Blinky.Domain;

namespace Blinky.AdcsConnector;

/// <summary>
/// The domain, read as the account this service runs as, for the API's directory
/// routes (0104).
/// </summary>
/// <remarks>
/// <para>
/// The API's own <see cref="LdapDirectory"/> with no bind DN, so it binds with
/// Negotiate from this process's Kerberos credentials: the same filters, the same SID
/// formatting and the same crossRef read as a direct bind, and no password. A second
/// implementation in ADSI would answer the same questions with different rules about
/// who counts as a person, which is the drift that makes "switch where the directory
/// is read" more than one setting.
/// </para>
/// <para>
/// Resolved at the first call and dropped after any failure. A service that runs for
/// weeks outlives the domain controller it first found; keeping a connection to one
/// that rebooted would answer every later call with the same dead socket.
/// </para>
/// </remarks>
public sealed class DomainDirectory(DirectoryOptions options, ILogger<DomainDirectory> logger)
    : IDirectory, IDisposable
{
    private readonly Lock gate = new();
    private LdapDirectory? current;

    public string? Host { get; private set; }

    public string? BaseDn { get; private set; }

    public DirectorySource Source => DirectorySource.ActiveDirectory;

    public Task<IReadOnlyList<DirectoryUser>> SearchAsync(string query, int limit = 20,
        CancellationToken ct = default) =>
        Use(directory => directory.SearchAsync(query, limit, ct));

    public Task<DirectoryUser?> FindAsync(string upnOrAccount, CancellationToken ct = default) =>
        Use(directory => directory.FindAsync(upnOrAccount, ct));

    public Task<IReadOnlyList<DirectoryUser>> MembersOfAsync(string group, int limit = 200,
        CancellationToken ct = default) =>
        Use(directory => directory.MembersOfAsync(group, limit, ct));

    public Task<DirectoryWriteAccess> CanWriteAsync(string subjectDn, CancellationToken ct = default) =>
        Use(directory => directory.CanWriteAsync(subjectDn, ct));

    public Task<string?> NetBiosDomainAsync(string distinguishedName, CancellationToken ct = default) =>
        Use(directory => directory.NetBiosDomainAsync(distinguishedName, ct));

    public async Task<DirectoryProbe> TestAsync(CancellationToken ct = default)
    {
        LdapDirectory directory;

        try
        {
            directory = Resolve();
        }
        catch (Exception ex)
        {
            return new DirectoryProbe(false, false, null, true, 0,
                "No domain controller to read: " + ex.Message
                + " The connector has to run as a domain account on a domain member.");
        }

        var probe = await directory.TestAsync(ct);

        if (!probe.Succeeded)
        {
            Drop(directory);
        }

        // LdapDirectory says "the container's own Kerberos credentials", which is true of
        // the API and not of a Windows service.
        return probe.BoundAs is null
            ? probe
            : probe with
            {
                BoundAs = Environment.UserDomainName + "\\" + Environment.UserName,
                Detail = $"Bound as {Environment.UserDomainName}\\{Environment.UserName} with "
                         + $"Kerberos and read {BaseDn} on {Host}.",
            };
    }

    private async Task<T> Use<T>(Func<IDirectory, Task<T>> call)
    {
        var directory = Resolve();

        try
        {
            return await call(directory);
        }
        catch
        {
            Drop(directory);
            throw;
        }
    }

    private LdapDirectory Resolve()
    {
        lock (gate)
        {
            if (current is not null)
            {
                return current;
            }

            var host = options.Host is { Length: > 0 } configured
                ? configured
                : System.DirectoryServices.ActiveDirectory.Domain.GetComputerDomain()
                    .FindDomainController().Name;

            var baseDn = options.BaseDn is { Length: > 0 } given ? given : NamingContextOf(host);

            current = new LdapDirectory(new LdapDirectoryOptions(
                host,
                options.Port,
                baseDn,
                DirectorySource.ActiveDirectory,
                BindDn: null,
                BindPassword: null,
                UseTls: true,
                NetBiosDomain: options.NetBiosDomain));

            Host = host;
            BaseDn = baseDn;

            logger.LogInformation(
                "Reading the directory at {Host}:{Port}, base {BaseDn}, as {Account}",
                host, options.Port, baseDn, Environment.UserDomainName + "\\" + Environment.UserName);

            return current;
        }
    }

    private static string NamingContextOf(string host)
    {
        using var rootDse = new System.DirectoryServices.DirectoryEntry($"LDAP://{host}/RootDSE");

        return rootDse.Properties["defaultNamingContext"].Value as string
               ?? throw new InvalidOperationException(
                   $"{host} did not name its default naming context. Set Connector:Directory:BaseDn.");
    }

    private void Drop(LdapDirectory failed)
    {
        lock (gate)
        {
            if (ReferenceEquals(current, failed))
            {
                current = null;
            }
        }

        failed.Dispose();
    }

    public void Dispose()
    {
        lock (gate)
        {
            current?.Dispose();
            current = null;
        }
    }
}
