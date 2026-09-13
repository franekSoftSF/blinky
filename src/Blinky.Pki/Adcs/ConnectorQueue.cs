using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Threading.Channels;
using Blinky.Contracts;

namespace Blinky.Pki.Adcs;

/// <summary>
/// Calls into the CA waiting for a connector to come and ask for them - the API's
/// half of the connector dialling the API rather than the other way round.
/// </summary>
/// <remarks>
/// <para>
/// In memory, and deliberately so. Every call here has a caller holding a request
/// open for the answer - an agent waiting for its certificate, an operator waiting
/// for a revocation - so a queue that outlived a restart would deliver answers to
/// nobody. What a restart can lose is a submission the connector had already made:
/// the CA issued, and nothing here recorded it. The direct transport loses the same
/// certificate when its HTTP call times out, and the CA's database is where both are
/// found.
/// </para>
/// <para>
/// <b>Two deadlines, not one.</b> A call nobody collects in <see cref="PickupTimeout"/>
/// fails fast with "no connector is asking", because that is a connector that is
/// down, not a CA that is slow, and the status page should say so in seconds. A call
/// that was collected waits for the whole <see cref="AnswerTimeout"/>, because the
/// connector serialises calls into the CA and a slow submission ahead of it is not a
/// fault.
/// </para>
/// </remarks>
public sealed class ConnectorQueue(TimeProvider? clock = null)
{
    private readonly TimeProvider time = clock ?? TimeProvider.System;
    private readonly Channel<Pending> waiting = Channel.CreateUnbounded<Pending>();
    private readonly ConcurrentDictionary<Guid, Pending> collected = new();
    private long lastPoll;

    public TimeSpan PickupTimeout { get; init; } = TimeSpan.FromSeconds(20);

    public TimeSpan AnswerTimeout { get; init; } = TimeSpan.FromSeconds(90);

    /// <summary>When a connector last asked for work, or null if none ever has.</summary>
    public DateTimeOffset? LastPoll =>
        Interlocked.Read(ref lastPoll) is var ticks and > 0 ? new DateTimeOffset(ticks, TimeSpan.Zero) : null;

    /// <summary>Hands a call to the next connector that asks, and waits for its answer.</summary>
    public async Task<(HttpStatusCode Status, string? Body)> SendAsync(
        string method, string path, string? body, CancellationToken ct)
    {
        var pending = new Pending(new AdcsWorkItem(AdcsTransport.SchemaVersion, Guid.NewGuid(), method, path, body));

        await waiting.Writer.WriteAsync(pending, ct);

        using var pickup = CancellationTokenSource.CreateLinkedTokenSource(ct);
        pickup.CancelAfter(PickupTimeout);

        var abandoned = false;

        try
        {
            await pending.Collected.Task.WaitAsync(pickup.Token);
        }
        catch (OperationCanceledException)
        {
            // Abandoned rather than removed: the channel cannot take an item back,
            // so the connector skips it when it gets there - and nothing is signed
            // for a caller who has gone. A call collected in the same instant is not
            // abandoned, and goes on to wait for its answer like any other.
            abandoned = pending.TryAbandon();

            if (abandoned && ct.IsCancellationRequested)
            {
                throw;
            }
        }

        if (abandoned)
        {
            throw new CertificateAuthorityException(
                $"No connector collected the call in {PickupTimeout.TotalSeconds:0}s. "
                + (LastPoll is { } seen
                    ? $"The last one asked for work at {seen:u}; it has stopped polling, or cannot reach the API."
                    : "None has asked for work since the API started: the connector is not running, "
                      + "cannot reach this API, or presents a certificate the API does not accept."));
        }

        using var answer = CancellationTokenSource.CreateLinkedTokenSource(ct);
        answer.CancelAfter(AnswerTimeout);

        try
        {
            var result = await pending.Answered.Task.WaitAsync(answer.Token);

            return ((HttpStatusCode)result.Status, result.Body);
        }
        catch (OperationCanceledException)
        {
            collected.TryRemove(pending.Item.Id, out _);

            if (ct.IsCancellationRequested)
            {
                throw;
            }

            throw new CertificateAuthorityException(
                $"The connector collected the call and did not answer within {AnswerTimeout.TotalSeconds:0}s. "
                + "It serialises calls into the CA, so a submission that overran leaves it busy until "
                + "the CA answers - and a submission may have been issued at the CA all the same.");
        }
    }

    /// <summary>The next call for a connector, or null when none arrived within the wait.</summary>
    public async Task<AdcsWorkItem?> NextAsync(TimeSpan wait, CancellationToken ct)
    {
        Interlocked.Exchange(ref lastPoll, time.GetUtcNow().UtcTicks);

        using var limit = CancellationTokenSource.CreateLinkedTokenSource(ct);
        limit.CancelAfter(wait);

        try
        {
            while (true)
            {
                var pending = await waiting.Reader.ReadAsync(limit.Token);

                if (pending.TryCollect())
                {
                    collected[pending.Item.Id] = pending;

                    return pending.Item;
                }
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return null;
        }
    }

    /// <summary>
    /// The answer to a call handed out earlier. False for one nobody is waiting for
    /// any more - timed out, or never handed out - which the connector logs.
    /// </summary>
    public bool Complete(AdcsWorkResult result) =>
        collected.TryRemove(result.Id, out var pending) && pending.Answered.TrySetResult(result);

    private sealed class Pending(AdcsWorkItem item)
    {
        private int state;

        public AdcsWorkItem Item { get; } = item;

        public TaskCompletionSource Collected { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource<AdcsWorkResult> Answered { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        /// <summary>Exactly one of collect or abandon wins, so nothing is signed for a caller who left.</summary>
        public bool TryCollect()
        {
            if (Interlocked.CompareExchange(ref state, 1, 0) != 0)
            {
                return false;
            }

            Collected.TrySetResult();

            return true;
        }

        public bool TryAbandon() => Interlocked.CompareExchange(ref state, 2, 0) == 0;
    }
}

/// <summary>
/// <see cref="ConnectorAdcsTransport"/> over the queue instead of a socket, so the
/// transport's contract checks, error sentences and version refusals are the same
/// code whichever side dialled.
/// </summary>
internal sealed class ConnectorQueueHandler(ConnectorQueue queue) : HttpMessageHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null
            ? null
            : await request.Content.ReadAsStringAsync(cancellationToken);

        var (status, answer) = await queue.SendAsync(
            request.Method.Method, request.RequestUri!.PathAndQuery, body, cancellationToken);

        return new HttpResponseMessage(status)
        {
            RequestMessage = request,
            Content = new StringContent(answer ?? string.Empty, Encoding.UTF8, "application/json"),
        };
    }
}
