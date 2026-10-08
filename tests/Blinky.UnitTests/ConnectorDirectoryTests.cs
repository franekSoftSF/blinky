using System.Net;
using System.Text;
using Blinky.AdcsConnector;
using Blinky.Api.Credentials;
using Blinky.Contracts;
using Blinky.Directory;
using Blinky.Domain;
using Blinky.Pki;
using Blinky.Pki.Adcs;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Blinky.UnitTests;

/// <summary>
/// Active Directory read by the ADCS connector on the API's behalf (0104): the API's
/// client, the queue a polling connector collects from, and the connector's routes, with
/// only the directory itself made up.
/// </summary>
public sealed class ConnectorDirectoryTests
{
    private const string Sid = "S-1-5-21-1004336348-1177238915-682003330-1105";

    private static readonly DirectoryUser Person = new(
        "szymon frankiewicz", "s.frankiewicz", "s.frankiewicz@ad.digitalworkspace.pl", Sid,
        "CN=szymon frankiewicz,OU=Users,DC=ad,DC=digitalworkspace,DC=pl", Enabled: true);

    [Fact]
    public async Task A_person_found_by_the_connector_arrives_as_a_direct_bind_would_return_them()
    {
        var directory = new RecordingDirectory { Found = Person };
        await using var wire = await Wire.Start(directory);

        var found = await wire.Api.FindAsync("s.frankiewicz@ad.digitalworkspace.pl");

        Assert.Equal(Person, found);
        Assert.Equal("s.frankiewicz@ad.digitalworkspace.pl", directory.LastValue);
    }

    [Fact]
    public async Task Nobody_is_null_rather_than_an_error()
    {
        await using var wire = await Wire.Start(new RecordingDirectory());

        Assert.Null(await wire.Api.FindAsync("nobody@ad.digitalworkspace.pl"));
    }

    [Fact]
    public async Task A_search_carries_its_limit_and_returns_everyone_found()
    {
        var directory = new RecordingDirectory { Many = [Person, Person with { SamAccountName = "s.other" }] };
        await using var wire = await Wire.Start(directory);

        var found = await wire.Api.SearchAsync("s.", 7);

        Assert.Equal(2, found.Count);
        Assert.Equal(("s.", 7), (directory.LastValue, directory.LastLimit));
    }

    [Fact]
    public async Task The_netbios_name_comes_from_the_connector_when_nothing_is_configured()
    {
        await using var wire = await Wire.Start(new RecordingDirectory { NetBios = "AD" });

        Assert.Equal("AD", await wire.Api.NetBiosDomainAsync(Person.DistinguishedName!));
    }

    [Fact]
    public async Task A_logon_name_resolves_end_to_end_through_the_connector()
    {
        // The reason this exists: a Microsoft CA issues only for DOMAIN\user, and the API
        // host no longer holds a password to read it with.
        await using var wire = await Wire.Start(new RecordingDirectory { Found = Person, NetBios = "AD" });

        var name = await new LogonNames(wire.Api, required: true).ResolveAsync(
            new CardholderRequest(Person.DisplayName, Person.Upn, Sid), default);

        Assert.Equal(@"AD\s.frankiewicz", name);
    }

    [Fact]
    public async Task A_connector_told_not_to_read_the_directory_says_so()
    {
        await using var wire = await Wire.Start(new NoDirectory());

        var refusal = await Assert.ThrowsAsync<CertificateAuthorityException>(
            () => wire.Api.FindAsync("s.frankiewicz"));

        Assert.Contains("does not read the directory", refusal.Message, StringComparison.Ordinal);
        Assert.Contains("Connector:Directory:Enabled", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_directory_that_fails_on_the_ca_server_is_a_502_naming_the_directory()
    {
        await using var wire = await Wire.Start(new RecordingDirectory { Fault = new InvalidOperationException("LDAP 81") });

        var refusal = await Assert.ThrowsAsync<CertificateAuthorityException>(
            () => wire.Api.FindAsync("s.frankiewicz"));

        Assert.Contains("502", refusal.Message, StringComparison.Ordinal);
        Assert.Contains("directory could not be read: LDAP 81", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_probe_reports_where_the_connector_read_and_never_throws()
    {
        await using var wire = await Wire.Start(new RecordingDirectory());

        var probe = await wire.Api.TestAsync();

        Assert.True(probe.Succeeded);
        Assert.StartsWith("Through the connector:", probe.Detail, StringComparison.Ordinal);

        using var dead = new ConnectorAdcsTransport(
            new ConnectorTransportOptions(new Uri("https://ca.test")),
            new FixedHandler(HttpStatusCode.BadGateway, null));

        Assert.False((await new ConnectorDirectory(dead).TestAsync()).Succeeded);
    }

    [Fact]
    public async Task A_connector_from_before_the_directory_routes_is_named_as_too_old()
    {
        using var old = new ConnectorAdcsTransport(
            new ConnectorTransportOptions(new Uri("https://ca.test")),
            new FixedHandler(HttpStatusCode.NotFound, null));

        var refusal = await Assert.ThrowsAsync<CertificateAuthorityException>(
            () => new ConnectorDirectory(old).FindAsync("s.frankiewicz"));

        Assert.Contains("older than 0104", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_account_name_travels_in_the_body_and_never_in_the_path()
    {
        var handler = new FixedHandler(HttpStatusCode.OK, """{"user":null}""");
        using var transport = new ConnectorAdcsTransport(
            new ConnectorTransportOptions(new Uri("https://ca.test")), handler);

        await new ConnectorDirectory(transport).FindAsync("s.frankiewicz@ad.digitalworkspace.pl");

        Assert.Equal(HttpMethod.Post, handler.Last!.Method);
        Assert.DoesNotContain("frankiewicz", handler.Last.RequestUri!.ToString(), StringComparison.Ordinal);
        Assert.Contains("frankiewicz", handler.LastBody, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_configured_netbios_name_is_answered_without_asking_the_connector()
    {
        var handler = new FixedHandler(HttpStatusCode.InternalServerError, null);
        using var transport = new ConnectorAdcsTransport(
            new ConnectorTransportOptions(new Uri("https://ca.test")), handler);

        Assert.Equal("AD", await new ConnectorDirectory(transport, "AD").NetBiosDomainAsync("DC=ad"));
        Assert.Null(handler.Last);
    }

    /// <summary>The API's client, a polling connector's queue, and the connector's own routes in memory.</summary>
    private sealed class Wire : IAsyncDisposable
    {
        private readonly WebApplication connector;
        private readonly ConnectorAdcsTransport transport;
        private readonly CancellationTokenSource stop = new();
        private readonly Task pump;

        private Wire(WebApplication connector, ConnectorQueue queue)
        {
            this.connector = connector;
            transport = new ConnectorAdcsTransport(queue, caConfig: null);
            Api = new ConnectorDirectory(transport);

            // What ApiPoller does in its loop, without the HTTP between the two.
            pump = Task.Run(async () =>
            {
                while (!stop.IsCancellationRequested)
                {
                    try
                    {
                        if (await queue.NextAsync(TimeSpan.FromSeconds(1), stop.Token) is { } item)
                        {
                            queue.Complete(await ApiPoller.Make(connector.GetTestServer(), item, "API", stop.Token));
                        }
                    }
                    catch (OperationCanceledException)
                    {
                    }
                }
            });
        }

        public ConnectorDirectory Api { get; }

        public static async Task<Wire> Start(IDirectory directory)
        {
            var builder = WebApplication.CreateBuilder();
            builder.WebHost.UseTestServer();
            builder.Services.AddRouting();
            builder.Services.AddSingleton(directory);
            builder.Services.AddSingleton(new ConnectorOptions());

            var app = builder.Build();
            app.MapDirectory();
            await app.StartAsync();

            return new Wire(app, new ConnectorQueue());
        }

        public async ValueTask DisposeAsync()
        {
            await stop.CancelAsync();
            await pump;
            transport.Dispose();
            await connector.DisposeAsync();
            stop.Dispose();
        }
    }

    private sealed class RecordingDirectory : IDirectory
    {
        public DirectoryUser? Found { get; init; }

        public IReadOnlyList<DirectoryUser> Many { get; init; } = [];

        public string? NetBios { get; init; }

        public Exception? Fault { get; init; }

        public string? LastValue { get; private set; }

        public int LastLimit { get; private set; }

        public DirectorySource Source => DirectorySource.ActiveDirectory;

        public Task<IReadOnlyList<DirectoryUser>> SearchAsync(string query, int limit = 20, CancellationToken ct = default)
        {
            (LastValue, LastLimit) = (query, limit);

            return Fault is null ? Task.FromResult(Many) : Task.FromException<IReadOnlyList<DirectoryUser>>(Fault);
        }

        public Task<DirectoryUser?> FindAsync(string upnOrAccount, CancellationToken ct = default)
        {
            LastValue = upnOrAccount;

            return Fault is null ? Task.FromResult(Found) : Task.FromException<DirectoryUser?>(Fault);
        }

        public Task<DirectoryProbe> TestAsync(CancellationToken ct = default) =>
            Task.FromResult(new DirectoryProbe(true, true, @"AD\svc_blinky", true, 3, "Bound."));

        public Task<IReadOnlyList<DirectoryUser>> MembersOfAsync(string group, int limit = 200, CancellationToken ct = default) =>
            SearchAsync(group, limit, ct);

        public Task<DirectoryWriteAccess> CanWriteAsync(string subjectDn, CancellationToken ct = default) =>
            Task.FromResult(DirectoryWriteAccess.Unknown("not asked"));

        public Task<string?> NetBiosDomainAsync(string distinguishedName, CancellationToken ct = default) =>
            Task.FromResult(NetBios);
    }

    private sealed class FixedHandler(HttpStatusCode status, string? body) : HttpMessageHandler
    {
        public HttpRequestMessage? Last { get; private set; }

        public string? LastBody { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Last = request;
            LastBody = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);

            return new HttpResponseMessage(status)
            {
                Content = new StringContent(body ?? string.Empty, Encoding.UTF8, "application/json"),
            };
        }
    }
}
