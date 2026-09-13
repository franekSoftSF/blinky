using System.Text.Json;
using Blinky.AdcsConnector;
using Blinky.Contracts;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Blinky.UnitTests;

/// <summary>
/// A call collected from the API, made through the connector's own endpoints in memory.
/// </summary>
public sealed class AdcsApiPollerTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    [Fact]
    public async Task A_posted_body_reaches_the_endpoint_as_it_would_over_a_socket()
    {
        // The first run against HZCS01 answered every POST with an empty 400: GETs went
        // through and a body did not.
        await using var app = await Host(endpoints =>
            endpoints.MapPost("/connector/sign", (AdcsSignRequest request, HttpContext context) =>
                Results.Ok(new AdcsSignResponse(request.PkiData + "|" + ConnectorCaller.Of(context)))));

        var result = await ApiPoller.Make(
            app.GetTestServer(),
            new AdcsWorkItem(AdcsTransport.SchemaVersion, Guid.NewGuid(), "POST", "/connector/sign",
                JsonSerializer.Serialize(new AdcsSignRequest(AdcsTransport.SchemaVersion, "AQID"), Json)),
            "API at https://api.test",
            default);

        Assert.Equal(200, result.Status);
        Assert.Equal("AQID|API at https://api.test",
            JsonSerializer.Deserialize<AdcsSignResponse>(result.Body!, Json)!.SignedData);
    }

    [Fact]
    public async Task A_query_string_reaches_the_endpoint()
    {
        await using var app = await Host(endpoints =>
            endpoints.MapGet("/connector/describe", (string? caConfig) => Results.Ok(caConfig)));

        var result = await ApiPoller.Make(
            app.GetTestServer(),
            new AdcsWorkItem(AdcsTransport.SchemaVersion, Guid.NewGuid(), "GET",
                "/connector/describe?caConfig=" + Uri.EscapeDataString(@"SUBCA\Issuing CA"), null),
            "API", default);

        Assert.Equal(@"SUBCA\Issuing CA", JsonSerializer.Deserialize<string>(result.Body!, Json));
    }

    [Theory]
    [InlineData("GET", "/api/anything")]
    [InlineData("GET", "/connector/../api/anything")]
    [InlineData("DELETE", "/connector/describe")]
    public async Task Nothing_but_a_connector_call_is_made_on_the_apis_behalf(string method, string path)
    {
        await using var app = await Host(_ => { });

        var result = await ApiPoller.Make(
            app.GetTestServer(),
            new AdcsWorkItem(AdcsTransport.SchemaVersion, Guid.NewGuid(), method, path, null),
            "API", default);

        Assert.Equal(400, result.Status);
        Assert.Contains("not a connector call", result.Body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_schema_this_connector_does_not_speak_is_refused_before_anything_runs()
    {
        await using var app = await Host(_ => { });

        var result = await ApiPoller.Make(
            app.GetTestServer(),
            new AdcsWorkItem(99, Guid.NewGuid(), "GET", "/connector/health", null),
            "API", default);

        Assert.Equal(400, result.Status);
        Assert.Contains("sent 99", result.Body, StringComparison.Ordinal);
    }

    private static async Task<WebApplication> Host(Action<WebApplication> map)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddRouting();

        var app = builder.Build();
        map(app);

        await app.StartAsync();

        return app;
    }
}
