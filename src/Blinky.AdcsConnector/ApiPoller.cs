using System.Net;
using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Blinky.Contracts;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.TestHost;

namespace Blinky.AdcsConnector;

/// <summary>
/// The connector dialling the API: collect a call, make it through this connector's
/// own endpoints, send back what they answered.
/// </summary>
/// <remarks>
/// <para>
/// The calls run through the same endpoints the listener serves, in memory. That is
/// the whole design: the refusals, the signature log and the CA's own error text
/// cannot differ between the two directions, because there is one copy of each. The
/// in-memory server is ASP.NET Core's <c>TestServer</c>, which is an <c>IServer</c>
/// with no socket - the name is about where it is usually used, not about what it is.
/// </para>
/// <para>
/// Only paths under <c>/connector/</c> are made. The API is trusted to ask for
/// enrolments and revocations, which is already a great deal; it is not given a way
/// to reach anything else this process might one day serve.
/// </para>
/// </remarks>
public sealed class ApiPoller(
    IServer server, ConnectorOptions options, ILogger<ApiPoller> logger) : BackgroundService
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var client = CreateClient(options.Api, out var identity);
        var memory = (TestServer)server;
        var caller = $"API at {options.Api.Url}";
        var wait = Math.Clamp(options.Api.WaitSeconds, 1, AdcsQueue.MaximumWaitSeconds);
        var failures = 0;

        logger.LogInformation(
            "Polling {Url} for calls, as client certificate {Fingerprint}",
            options.Api.Url, ClientCertificateGate.FingerprintOf(identity));

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var response = await client.GetAsync($"{AdcsQueue.NextPath}?wait={wait}", stoppingToken);

                if (!response.IsSuccessStatusCode)
                {
                    // 401 is the one worth spelling out: the API reached, and this
                    // certificate is not on its list, or not from a CA the edge trusts.
                    throw new HttpRequestException(
                        $"{(int)response.StatusCode} {await Text(response, stoppingToken)}"
                        + (response.StatusCode == HttpStatusCode.Unauthorized
                            ? " - the API does not accept this certificate as a connector's: its chain must end at "
                              + "the agent CA and its SHA-256 must be in Blinky:Adcs:Connector:ClientFingerprints"
                            : string.Empty));
                }

                if (failures > 0)
                {
                    logger.LogInformation("Reached {Url} again after {Failures} failed poll(s)", options.Api.Url, failures);
                    failures = 0;
                }

                if (response.StatusCode == HttpStatusCode.NoContent)
                {
                    continue;
                }

                var item = await response.Content.ReadFromJsonAsync<AdcsWorkItem>(Json, stoppingToken)
                           ?? throw new HttpRequestException("The API answered a poll with an empty body.");

                var result = await Make(memory, item, caller, stoppingToken);

                using var posted = await client.PostAsJsonAsync(AdcsQueue.ResultPath, result, Json, stoppingToken);

                if (posted.StatusCode == HttpStatusCode.Gone)
                {
                    // The work was done and nobody is waiting for it. For a submission
                    // that is a certificate at the CA that Blinky has no record of,
                    // so it is logged as the thing to go and look for.
                    logger.LogWarning(
                        "The API had stopped waiting for {Method} {Path} (call {Id}) by the time it was answered "
                        + "{Status}. A submission answered after that may be an issued certificate Blinky does not hold",
                        item.Method, item.Path, item.Id, result.Status);
                }
                else if (!posted.IsSuccessStatusCode)
                {
                    logger.LogWarning(
                        "The API refused the answer to call {Id}: {Status} {Body}",
                        item.Id, (int)posted.StatusCode, await Text(posted, stoppingToken));
                }
            }
            catch (Exception ex) when (!stoppingToken.IsCancellationRequested
                                       && ex is HttpRequestException or TaskCanceledException or JsonException)
            {
                failures++;

                // Every failure at first, then one in ten, so a network outage over a
                // weekend is a few hundred lines rather than a disk.
                if (failures <= 3 || failures % 10 == 0)
                {
                    logger.LogWarning("Poll {Failures} to {Url} failed: {Reason}", failures, options.Api.Url,
                        ex.InnerException is { } inner ? $"{ex.Message} ({inner.Message})" : ex.Message);
                }

                // Capped under the API's pickup deadline, so a call waiting when the API
                // comes back is collected rather than failed for a connector still asleep.
                await Task.Delay(TimeSpan.FromSeconds(Math.Min(15, 2 * failures)), stoppingToken);
            }
        }
    }

    /// <summary>One call, through this connector's own endpoints, as the API asked for it.</summary>
    internal static async Task<AdcsWorkResult> Make(
        TestServer memory, AdcsWorkItem item, string caller, CancellationToken ct)
    {
        if (!AdcsTransport.IsSupported(item.SchemaVersion))
        {
            return Refusal(item, HttpStatusCode.BadRequest,
                $"This connector speaks schema {AdcsTransport.MinimumSupportedVersion} to "
                + $"{AdcsTransport.MaximumSupportedVersion} and was sent {item.SchemaVersion}.");
        }

        if (!item.Path.StartsWith("/connector/", StringComparison.Ordinal)
            || item.Path.Contains("..", StringComparison.Ordinal)
            || item.Method is not ("GET" or "POST"))
        {
            return Refusal(item, HttpStatusCode.BadRequest,
                $"{item.Method} {item.Path} is not a connector call, and nothing else is made on the API's behalf.");
        }

        var query = item.Path.IndexOf('?');

        try
        {
            var context = await memory.SendAsync(http =>
            {
                http.Request.Method = item.Method;
                http.Request.Path = query < 0 ? item.Path : item.Path[..query];
                http.Request.QueryString = query < 0 ? QueryString.Empty : new QueryString(item.Path[query..]);
                http.Request.Headers[AdcsTransport.SchemaHeader] = AdcsTransport.SchemaVersion.ToString();
                http.Items[ConnectorCaller.ItemKey] = caller;

                if (item.Body is { } body)
                {
                    var bytes = Encoding.UTF8.GetBytes(body);
                    http.Request.ContentType = "application/json";
                    http.Request.ContentLength = bytes.Length;
                    http.Request.Body = new MemoryStream(bytes);

                    // TestServer decides whether a request can have a body before this runs,
                    // from a request that had none yet, and minimal APIs believe it: every
                    // POST reached HZCS01 as an empty 400 until this was said explicitly.
                    http.Features.Set<IHttpRequestBodyDetectionFeature>(HasBody.Instance);
                }
            }, ct);

            using var reader = new StreamReader(context.Response.Body, Encoding.UTF8);

            return new AdcsWorkResult(
                AdcsTransport.SchemaVersion, item.Id, context.Response.StatusCode, await reader.ReadToEndAsync(ct));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Refusal(item, HttpStatusCode.InternalServerError, "The connector failed to make the call: " + ex.Message);
        }
    }

    private static AdcsWorkResult Refusal(AdcsWorkItem item, HttpStatusCode status, string reason) =>
        new(AdcsTransport.SchemaVersion, item.Id, (int)status, JsonSerializer.Serialize(new AdcsProblem(reason), Json));

    private static async Task<string> Text(HttpResponseMessage response, CancellationToken ct)
    {
        var text = await response.Content.ReadAsStringAsync(ct);

        return text.Length > 300 ? text[..300] : text;
    }

    /// <summary>
    /// A client that presents the connector's certificate and believes only the API it
    /// was told about: a pinned SHA-256, or a chain this machine trusts naming the host.
    /// </summary>
    internal static HttpClient CreateClient(ApiOptions api, out X509Certificate2 identity)
    {
        if (!Uri.TryCreate(api.Url, UriKind.Absolute, out var url) || url.Scheme != Uri.UriSchemeHttps)
        {
            throw new InvalidOperationException(
                "Connector:Api:Url has to be an absolute https address. What comes back on it is "
                + "PKIData to sign as the enrolment agent.");
        }

        var (certificate, _) = ServerCertificate.Load(api.ClientCertificate, "Connector:Api:ClientCertificate");
        identity = certificate;

        var pinned = api.ServerFingerprint is { Length: > 0 } configured
            ? ClientCertificateGate.Normalise(configured)
            : null;

        if (pinned is { Length: not 64 })
        {
            throw new InvalidOperationException(
                "Connector:Api:ServerFingerprint is not a SHA-256 fingerprint: a 40-digit value is the "
                + "SHA-1 thumbprint, which is a different field.");
        }

        var handler = new HttpClientHandler
        {
            SslProtocols = System.Security.Authentication.SslProtocols.Tls12
                           | System.Security.Authentication.SslProtocols.Tls13,
            ServerCertificateCustomValidationCallback = (_, presented, _, errors) =>
                presented is not null
                && (pinned is null
                    ? errors == SslPolicyErrors.None
                    : string.Equals(presented.GetCertHashString(HashAlgorithmName.SHA256), pinned, StringComparison.Ordinal)),
        };

        handler.ClientCertificates.Add(certificate);

        return new HttpClient(handler)
        {
            BaseAddress = url,

            // Longer than a poll is held open, so a quiet API is a 204 and not a timeout.
            Timeout = TimeSpan.FromSeconds(AdcsQueue.MaximumWaitSeconds + 35),
        };
    }
}

internal sealed class HasBody : IHttpRequestBodyDetectionFeature
{
    public static readonly HasBody Instance = new();

    public bool CanHaveBody => true;
}

/// <summary>Who asked, for the signature and revocation logs, in either direction.</summary>
public static class ConnectorCaller
{
    public const string ItemKey = "blinky.caller";

    public static string Of(HttpContext context) =>
        context.Items.TryGetValue(ItemKey, out var caller) && caller is string named
            ? named
            : context.Connection.ClientCertificate is { } presented
                ? ClientCertificateGate.FingerprintOf(presented)
                : "none";
}
