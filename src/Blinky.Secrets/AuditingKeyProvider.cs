using System.Collections.Concurrent;

namespace Blinky.Secrets;

/// <summary>
/// Every use of a master secret, counted and announced, with none of it in the
/// record.
/// </summary>
/// <remarks>
/// <para>
/// A decorator rather than something each provider does for itself, so that
/// there is exactly one place where the question "what is safe to write down"
/// is answered, and adding a provider cannot get it wrong.
/// </para>
/// <para>
/// What is recorded: which key, which purpose, which generation, how many bytes
/// went in, how long it took, and whether it worked. What is never recorded:
/// the input and the output. The input to a management-key derivation is a
/// domain string and a serial, which is harmless, but the input to the envelope
/// derivation is not something worth a policy exception - and a rule that holds
/// for one caller and not the other is a rule that will be broken by the third.
/// This is the same instinct as the APDU redaction in <c>Blinky.Piv</c>, which
/// was a real defect once.
/// </para>
/// </remarks>
public sealed class AuditingKeyProvider(IKeyProvider inner, Action<KeyUse> sink) : IKeyProvider
{
    private readonly ConcurrentDictionary<KeyRef, KeyUsage> usage = new();

    public string Name => inner.Name;

    public KeyCustody Custody => inner.Custody;

    public IReadOnlyCollection<KeyDescription> Keys => inner.Keys;

    /// <summary>What has been done with each key since this process started.</summary>
    /// <remarks>
    /// Since this process started, not since the deployment existed. A counter
    /// that resets on restart is worth having and worth labelling; one that
    /// pretends to be a history is not.
    /// </remarks>
    public IReadOnlyDictionary<KeyRef, KeyUsage> Usage => usage;

    public bool Has(KeyRef key) => inner.Has(key);

    public byte[] Mac(KeyRef key, ReadOnlySpan<byte> data)
    {
        var started = System.Diagnostics.Stopwatch.GetTimestamp();
        var length = data.Length;

        try
        {
            var result = inner.Mac(key, data);

            Record(key, length, started, outcome: null);

            return result;
        }
        catch (Exception e)
        {
            Record(key, length, started, e.Message);

            throw;
        }
    }

    public void Dispose() => inner.Dispose();

    private void Record(KeyRef key, int inputLength, long started, string? outcome)
    {
        var elapsed = System.Diagnostics.Stopwatch.GetElapsedTime(started);
        var at = DateTimeOffset.UtcNow;

        usage.AddOrUpdate(
            key,
            _ => new KeyUsage(1, outcome is null ? 0 : 1, at),
            (_, previous) => previous with
            {
                Operations = previous.Operations + 1,
                Failures = previous.Failures + (outcome is null ? 0 : 1),
                LastUsedAt = at,
            });

        sink(new KeyUse(key, inner.Name, "hmac-sha256", inputLength, elapsed, outcome));
    }
}

/// <summary>
/// One use of one key. Carries no key material and no operation data by
/// construction: there is no field for either.
/// </summary>
/// <param name="Failure">
/// Why it did not work, or null when it did. A message from the module, which
/// is a return value and a mechanism name rather than anything derived.
/// </param>
public sealed record KeyUse(
    KeyRef Key,
    string Provider,
    string Operation,
    int InputBytes,
    TimeSpan Elapsed,
    string? Failure);

/// <summary>Running totals for one key, for the status page.</summary>
public sealed record KeyUsage(long Operations, long Failures, DateTimeOffset LastUsedAt)
{
    public long Operations { get; init; } = Operations;

    public long Failures { get; init; } = Failures;

    public DateTimeOffset LastUsedAt { get; init; } = LastUsedAt;
}
