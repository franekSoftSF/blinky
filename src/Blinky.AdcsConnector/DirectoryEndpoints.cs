using Blinky.Contracts;
using Blinky.Directory;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Blinky.AdcsConnector;

/// <summary>
/// The directory, read for the API by the account the connector runs as (0104).
/// </summary>
/// <remarks>
/// Reads only, and nothing decided here: which person a certificate is for, and
/// whether their SID still matches the enrolment, is still <c>LogonNames</c> on the
/// other side. This answers what the directory says, as a direct bind would.
/// </remarks>
public static class DirectoryEndpoints
{
    private const int MaximumValue = 1024;
    private const int MaximumList = 500;

    public static void MapDirectory(this IEndpointRouteBuilder app)
    {
        app.MapPost(ConnectorDirectoryPaths.Probe, async (
            IDirectory directory, CancellationToken ct) =>
        {
            if (Disabled(directory) is { } refused)
            {
                return refused;
            }

            // Not bounded like the others: TestAsync never throws, it reports, and a
            // probe that timed out here would lose the sentence saying which step hung.
            var probe = await directory.TestAsync(ct);
            var domain = directory as DomainDirectory;

            return Results.Ok(new ConnectorDirectoryProbe(
                probe.Reachable, probe.BaseDnFound, probe.BoundAs, probe.Encrypted,
                probe.Milliseconds, probe.Detail, domain?.Host, domain?.BaseDn));
        });

        app.MapPost(ConnectorDirectoryPaths.Search, (
            ConnectorDirectoryRequest request, IDirectory directory, ConnectorOptions options,
            CancellationToken ct) =>
            Read(directory, request, options, async d =>
                new ConnectorDirectoryUsers(
                    (await d.SearchAsync(request.Value, Limit(request, 20), ct)).Select(Wire).ToList()), ct));

        app.MapPost(ConnectorDirectoryPaths.Find, (
            ConnectorDirectoryRequest request, IDirectory directory, ConnectorOptions options,
            CancellationToken ct) =>
            Read(directory, request, options, async d =>
                new ConnectorDirectoryFound(await d.FindAsync(request.Value, ct) is { } user ? Wire(user) : null), ct));

        app.MapPost(ConnectorDirectoryPaths.Members, (
            ConnectorDirectoryRequest request, IDirectory directory, ConnectorOptions options,
            CancellationToken ct) =>
            Read(directory, request, options, async d =>
                new ConnectorDirectoryUsers(
                    (await d.MembersOfAsync(request.Value, Limit(request, 200), ct)).Select(Wire).ToList()), ct));

        app.MapPost(ConnectorDirectoryPaths.WriteAccess, (
            ConnectorDirectoryRequest request, IDirectory directory, ConnectorOptions options,
            CancellationToken ct) =>
            Read(directory, request, options, async d =>
            {
                var access = await d.CanWriteAsync(request.Value, ct);

                return new ConnectorDirectoryWriteAccess(
                    access.Determined, access.UserCertificate, access.AltSecurityIdentities, access.Detail);
            }, ct));

        app.MapPost(ConnectorDirectoryPaths.NetBios, (
            ConnectorDirectoryRequest request, IDirectory directory, ConnectorOptions options,
            CancellationToken ct) =>
            Read(directory, request, options, async d =>
                new ConnectorDirectoryNetBios(await d.NetBiosDomainAsync(request.Value, ct)), ct));
    }

    private static async Task<IResult> Read<T>(
        IDirectory directory, ConnectorDirectoryRequest? request, ConnectorOptions options,
        Func<IDirectory, Task<T>> read, CancellationToken ct)
    {
        if (Disabled(directory) is { } refused)
        {
            return refused;
        }

        if (request?.Value is null || request.Value.Length > MaximumValue)
        {
            return Results.Json(
                new AdcsProblem($"A directory request carries a value of at most {MaximumValue} characters."),
                statusCode: StatusCodes.Status400BadRequest);
        }

        try
        {
            // Bounded for the reason every CA call here is: a domain controller that
            // does not answer would otherwise hold the API's queue item until it gives up.
            return Results.Ok(await read(directory)
                .WaitAsync(TimeSpan.FromSeconds(Math.Max(5, options.RequestTimeoutSeconds)), ct));
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            // 502 naming the directory, so the API reports a domain it could not read
            // rather than a CA that failed.
            return Results.Json(
                new AdcsProblem("The directory could not be read: " + ex.Message,
                    "The connector reads the domain as the account it runs as; a local account "
                    + "on a domain member cannot, and a domain controller has to be reachable "
                    + "on " + options.Directory.Port + "."),
                statusCode: StatusCodes.Status502BadGateway);
        }
    }

    private static IResult? Disabled(IDirectory directory) =>
        directory is NoDirectory
            ? Results.Json(
                new AdcsProblem("This connector does not read the directory.",
                    "Connector:Directory:Enabled is false on the CA server."),
                statusCode: StatusCodes.Status404NotFound)
            : null;

    private static int Limit(ConnectorDirectoryRequest request, int otherwise) =>
        request.Limit <= 0 ? otherwise : Math.Min(request.Limit, MaximumList);

    private static ConnectorDirectoryUser Wire(DirectoryUser user) =>
        new(user.DisplayName, user.SamAccountName, user.Upn, user.ObjectSid,
            user.DistinguishedName, user.Enabled);
}
