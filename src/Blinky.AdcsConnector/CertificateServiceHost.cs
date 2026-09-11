namespace Blinky.AdcsConnector;

/// <summary>
/// Runs the blocking COM calls off the request thread, one at a time, with a
/// deadline.
/// </summary>
/// <remarks>
/// <para>
/// Serialised on purpose. <c>ICertRequest3</c> is not documented as safe to
/// call concurrently from one process, the CA behind it is a single database,
/// and the load this connector produces is one certificate per enrolment
/// ceremony - a person, plugging in a token. Buying parallelism here would be
/// paying with the one property that makes a failure readable: when two
/// requests are in flight and one hangs, nothing in the CA's log says which.
/// </para>
/// <para>
/// The deadline bounds the caller's wait and not the call. Aborting a DCOM call
/// in flight is not something the platform offers, so a timed-out submission
/// keeps its thread inside DCOM until the CA answers or the channel dies - and
/// keeps the lock, deliberately. Releasing it on the timeout would start a
/// second call into a CA that has not finished the first, which is the state
/// this class exists to prevent. Callers queueing behind it are told the
/// connector is busy, with the deadline in the message.
/// </para>
/// </remarks>
public sealed class CertificateServiceHost(
    ICertificateServices services,
    ConnectorOptions options,
    ILogger<CertificateServiceHost> logger)
{
    private readonly SemaphoreSlim gate = new(1, 1);

    public async Task<T> RunAsync<T>(
        string what, Func<ICertificateServices, CancellationToken, T> work, CancellationToken ct)
    {
        var deadline = TimeSpan.FromSeconds(Math.Max(5, options.RequestTimeoutSeconds));

        using var queueing = CancellationTokenSource.CreateLinkedTokenSource(ct);
        queueing.CancelAfter(deadline);

        try
        {
            await gate.WaitAsync(queueing.Token);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new CertificateServiceException(
                what + " waited " + deadline.TotalSeconds + "s behind another request to the "
                + "certification authority and gave up.");
        }

        // Released when the COM call returns, however long that takes, rather
        // than when this method stops waiting for it.
        var call = Task.Run(() => work(services, CancellationToken.None), CancellationToken.None);
        _ = call.ContinueWith(
            _ => gate.Release(), CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);

        try
        {
            return await call.WaitAsync(deadline, ct);
        }
        catch (TimeoutException)
        {
            logger.LogError(
                "{What} did not come back from the certification authority within {Seconds}s. "
                + "The connector stays busy until the call returns.",
                what, deadline.TotalSeconds);

            throw new CertificateServiceException(
                what + " did not come back from the certification authority within "
                + deadline.TotalSeconds + "s.");
        }
    }
}
