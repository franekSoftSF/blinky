using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Blinky.Passkeys;

namespace Blinky.UnitTests;

/// <summary>A provider that answers from a queue and remembers what it was asked.</summary>
internal sealed class FakeProvider : HttpMessageHandler
{
    private readonly Queue<Func<HttpResponseMessage>> answers = new();

    public List<Call> Calls { get; } = [];

    public HttpClient Client => new(this);

    public FakeProvider Answer(object? body = null, HttpStatusCode status = HttpStatusCode.OK,
        Action<HttpResponseMessage>? shape = null)
    {
        answers.Enqueue(() =>
        {
            var response = new HttpResponseMessage(status);

            if (body is not null)
            {
                var json = body as string ?? JsonSerializer.Serialize(body);
                response.Content = new StringContent(json, Encoding.UTF8, "application/json");
            }

            shape?.Invoke(response);
            return response;
        });

        return this;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
        Calls.Add(new Call(request.Method, request.RequestUri!, body, request.Headers.Authorization?.ToString()));

        Assert.True(answers.Count > 0, $"Unexpected {request.Method} {request.RequestUri}");
        return answers.Dequeue()();
    }

    internal sealed record Call(HttpMethod Method, Uri Uri, string? Body, string? Authorization)
    {
        public JsonElement Json => JsonDocument.Parse(Body!).RootElement;

        public Dictionary<string, string> Form => Body!.Split('&')
            .Select(p => p.Split('=', 2))
            .ToDictionary(p => WebUtility.UrlDecode(p[0]), p => WebUtility.UrlDecode(p[1]));
    }
}

/// <summary>A token that says whether it was asked for afresh.</summary>
internal sealed class CountingAuthorization : IProviderAuthorization
{
    public List<bool> Requests { get; } = [];

    public Task<AuthenticationHeaderValue> GetAsync(bool refresh, CancellationToken ct)
    {
        Requests.Add(refresh);
        return Task.FromResult(new AuthenticationHeaderValue("Bearer", refresh ? "FRESH" : "CACHED"));
    }
}

/// <summary>Time that stands still, and waits that end at once but are remembered.</summary>
internal sealed class FakeTime(DateTimeOffset now) : TimeProvider
{
    public DateTimeOffset Now { get; set; } = now;

    public List<TimeSpan> Waits { get; } = [];

    public override DateTimeOffset GetUtcNow() => Now;

    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        Waits.Add(dueTime);
        ThreadPool.QueueUserWorkItem(_ => callback(state));
        return new Stopped();
    }

    private sealed class Stopped : ITimer
    {
        public bool Change(TimeSpan dueTime, TimeSpan period) => true;

        public void Dispose()
        {
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
