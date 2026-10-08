using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace Blinky.Passkeys;

/// <summary>The calls both providers make, and the three things that go wrong with them.</summary>
internal sealed class ProviderHttp(
    HttpClient http,
    IProviderAuthorization authorization,
    string label,
    Func<JsonElement, string?> errorDetail,
    TimeProvider time)
{
    internal const int MaxThrottleRetries = 3;
    internal static readonly TimeSpan MaxThrottleWait = TimeSpan.FromSeconds(30);

    public Task<JsonDocument?> GetAsync(Uri uri, CancellationToken ct) =>
        SendAsync(HttpMethod.Get, uri, null, ct);

    public Task<JsonDocument?> PostAsync(Uri uri, object body, CancellationToken ct) =>
        SendAsync(HttpMethod.Post, uri, body, ct);

    public Task<JsonDocument?> DeleteAsync(Uri uri, CancellationToken ct) =>
        SendAsync(HttpMethod.Delete, uri, null, ct);

    /// <returns>The body, or null when there was none (204).</returns>
    public async Task<JsonDocument?> SendAsync(HttpMethod method, Uri uri, object? body, CancellationToken ct)
    {
        var refreshed = false;
        var throttled = 0;

        while (true)
        {
            using var request = new HttpRequestMessage(method, uri);
            request.Headers.Authorization = await authorization.GetAsync(refreshed, ct);
            request.Headers.Accept.ParseAdd("application/json");

            if (body is not null)
            {
                request.Content = JsonContent.Create(body);
            }

            HttpResponseMessage response;

            try
            {
                response = await http.SendAsync(request, ct);
            }
            catch (HttpRequestException e)
            {
                throw new PasskeyDirectoryException($"{label}: {e.Message}", null, e);
            }

            using (response)
            {
                if (response.StatusCode == HttpStatusCode.Unauthorized && !refreshed)
                {
                    refreshed = true;
                    continue;
                }

                // Graph throttles per tenant and per app. Waiting the time it names
                // is cheaper than a job failing on a call that would have worked.
                if (response.StatusCode == HttpStatusCode.TooManyRequests && throttled < MaxThrottleRetries)
                {
                    throttled++;
                    await Task.Delay(RetryAfter(response), time, ct);
                    continue;
                }

                var document = await ReadAsync(response, ct);

                if (!response.IsSuccessStatusCode)
                {
                    var detail = document is null ? null : errorDetail(document.RootElement);
                    document?.Dispose();

                    throw new PasskeyDirectoryException(
                        $"{label}: HTTP {(int)response.StatusCode}" + (detail is null ? "" : $" - {detail}"),
                        (int)response.StatusCode);
                }

                return document;
            }
        }
    }

    internal static TimeSpan RetryAfter(HttpResponseMessage response)
    {
        var wait = response.Headers.RetryAfter?.Delta ?? TimeSpan.FromSeconds(2);

        return wait < TimeSpan.FromSeconds(1) ? TimeSpan.FromSeconds(1)
            : wait > MaxThrottleWait ? MaxThrottleWait
            : wait;
    }

    private static async Task<JsonDocument?> ReadAsync(HttpResponseMessage response, CancellationToken ct)
    {
        var bytes = await response.Content.ReadAsByteArrayAsync(ct);

        if (bytes.Length == 0)
        {
            return null;
        }

        try
        {
            return JsonDocument.Parse(bytes);
        }
        catch (JsonException) when (!response.IsSuccessStatusCode)
        {
            // An HTML error page from a proxy. The status says enough.
            return null;
        }
    }

    /// <summary><c>message</c>, <c>error_description</c> or <c>error</c>, whichever is there.</summary>
    public static string? GenericDetail(JsonElement body) =>
        body.ValueKind != JsonValueKind.Object ? null
            : Json.Text(body, "message") ?? Json.Text(body, "error_description") ?? Json.Text(body, "error");
}

/// <summary>Reading provider JSON without trusting its shape.</summary>
internal static class Json
{
    public static string? Text(JsonElement parent, string name) =>
        parent.ValueKind == JsonValueKind.Object && parent.TryGetProperty(name, out var v)
            && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    public static JsonElement? Child(JsonElement parent, string name) =>
        parent.ValueKind == JsonValueKind.Object && parent.TryGetProperty(name, out var v)
            && v.ValueKind is not (JsonValueKind.Null or JsonValueKind.Undefined) ? v : null;

    public static bool? Flag(JsonElement parent, string name) =>
        Child(parent, name) is { ValueKind: JsonValueKind.True or JsonValueKind.False } v ? v.GetBoolean() : null;

    public static DateTimeOffset? Time(JsonElement parent, string name) =>
        Text(parent, name) is { } s && DateTimeOffset.TryParse(s, System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal, out var t) ? t : null;

    public static JsonElement Required(JsonElement parent, string name, string label) =>
        Child(parent, name) ?? throw new PasskeyDirectoryException($"{label}: the answer has no '{name}'.");
}
