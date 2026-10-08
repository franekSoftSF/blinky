namespace Blinky.Contracts;

/// <summary>
/// Directory reads made by the ADCS connector, as the domain account it already runs
/// as, on the API's behalf.
/// </summary>
/// <remarks>
/// <para>
/// Why the connector and not the API: an API in a Linux container reaches Active
/// Directory with a bind DN and a password that has to live in its <c>.env</c>, and
/// the connector is a domain member running as that same integration account, which
/// reaches the directory with Kerberos and holds no password at all. One account, one
/// process on the CA server, both halves of "issue for <c>DOMAIN\user</c>".
/// </para>
/// <para>
/// Additive to <see cref="AdcsTransport"/> schema 1. A connector built before these
/// routes answers 404 for them, which the API reports as a connector too old to read
/// the directory rather than as a directory with nobody in it.
/// </para>
/// <para>
/// POST with the value in the body, even for reads: an account name in a query string
/// lands in every request log on the way, and these are people.
/// </para>
/// </remarks>
public static class ConnectorDirectoryPaths
{
    public const string Probe = "/connector/directory/probe";
    public const string Search = "/connector/directory/search";
    public const string Find = "/connector/directory/find";
    public const string Members = "/connector/directory/members";
    public const string WriteAccess = "/connector/directory/write-access";
    public const string NetBios = "/connector/directory/netbios";
}

/// <param name="Value">
/// What is asked about: a search prefix, a UPN or account name, a group, or a
/// distinguished name, depending on the route.
/// </param>
/// <param name="Limit">How many people at most, for the routes that return a list.</param>
public sealed record ConnectorDirectoryRequest(string Value, int Limit = 0);

/// <summary>One person, as <c>Blinky.Directory.DirectoryUser</c> carries them.</summary>
/// <param name="ObjectSid">The SID in S-1-5-21-… form, formatted on the connector.</param>
public sealed record ConnectorDirectoryUser(
    string DisplayName,
    string? SamAccountName,
    string? Upn,
    string? ObjectSid,
    string? DistinguishedName,
    bool Enabled);

public sealed record ConnectorDirectoryUsers(IReadOnlyList<ConnectorDirectoryUser> Users);

/// <param name="User">Null for nobody and for more than one, as a direct read answers.</param>
public sealed record ConnectorDirectoryFound(ConnectorDirectoryUser? User);

/// <param name="Host">The domain controller the connector read, for the settings page.</param>
/// <param name="BaseDn">The naming context it searched.</param>
public sealed record ConnectorDirectoryProbe(
    bool Reachable,
    bool BaseDnFound,
    string? BoundAs,
    bool Encrypted,
    int Milliseconds,
    string Detail,
    string? Host,
    string? BaseDn);

public sealed record ConnectorDirectoryWriteAccess(
    bool Determined,
    bool UserCertificate,
    bool AltSecurityIdentities,
    string Detail);

public sealed record ConnectorDirectoryNetBios(string? Name);
