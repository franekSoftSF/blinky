namespace Blinky.Agent.Service;

/// <summary>
/// One card operation at a time, per process.
/// </summary>
/// <remarks>
/// <para>
/// <c>SCardConnect</c> takes the card exclusively. Until now the agent had one
/// thing that touched a reader — the poll loop — and got away with no
/// coordination at all. It still bit us: an inventory sweep on a short interval
/// and a job on the same reader produced <c>0x8010000B</c>, the job failing
/// instantly with no prompt and nothing naming the agent's own housekeeping as
/// the cause.
/// </para>
/// <para>
/// The tray makes that certain rather than likely, because now a person clicking
/// competes with a poll on a timer. So: everything that opens a reader takes
/// this first, and waits rather than failing. Waiting for a sweep to finish is
/// a moment; failing is a support call.
/// </para>
/// </remarks>
public sealed class CardGate : IDisposable
{
    private readonly SemaphoreSlim gate = new(1, 1);

    /// <summary>
    /// Long enough for a sweep of several readers, short enough that a
    /// deadlocked holder surfaces as an error rather than a hang.
    /// </summary>
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);

    public async Task<IDisposable> AcquireAsync(CancellationToken ct)
    {
        if (!await gate.WaitAsync(Timeout, ct))
        {
            throw new TimeoutException(
                "Another operation has held the card reader for longer than expected.");
        }

        return new Release(gate);
    }

    /// <summary>For the synchronous card paths, which are most of them.</summary>
    public IDisposable Acquire()
    {
        if (!gate.Wait(Timeout))
        {
            throw new TimeoutException(
                "Another operation has held the card reader for longer than expected.");
        }

        return new Release(gate);
    }

    public void Dispose() => gate.Dispose();

    private sealed class Release(SemaphoreSlim gate) : IDisposable
    {
        private int released;

        public void Dispose()
        {
            // Interlocked because a double dispose would raise the count above
            // one and let two operations onto the reader at once - the exact
            // thing this class exists to prevent.
            if (Interlocked.Exchange(ref released, 1) == 0)
            {
                gate.Release();
            }
        }
    }
}
