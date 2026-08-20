using System.Text.Json;
using Blinky.Piv;

namespace Blinky.UnitTests;

/// <summary>
/// Replays a recorded APDU exchange. Strict: it asserts that the caller sends
/// exactly the commands that were recorded, in order, so a change to how a
/// command is encoded fails the test rather than silently talking to a card
/// differently than the probe did.
/// </summary>
internal sealed class TranscriptTransport(IReadOnlyList<TranscriptTransport.Exchange> exchanges)
    : IApduTransport
{
    private int position;

    public string Description => "recorded transcript";

    public int Remaining => exchanges.Count - position;

    public IReadOnlyList<Exchange> Exchanges => exchanges;

    public static TranscriptTransport FromFixture(string fileName)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Fixtures", fileName);
        var entries = JsonSerializer.Deserialize<List<Entry>>(File.ReadAllText(path))
                      ?? throw new InvalidOperationException($"{fileName} is empty");

        return new TranscriptTransport(entries.Select(e => new Exchange(
            e.Label,
            Convert.FromHexString(e.Command),
            Convert.FromHexString(e.Response),
            Convert.ToUInt16(e.Sw, 16))).ToList());
    }

    /// <summary>A transport that answers a fixed script, for hand-built cases.</summary>
    public static TranscriptTransport Scripted(params Exchange[] exchanges) => new(exchanges);

    public ApduResponse Transmit(ReadOnlySpan<byte> apdu)
    {
        if (position >= exchanges.Count)
        {
            throw new PivProtocolException(
                $"The transcript ran out; unexpected command {Convert.ToHexString(apdu)}");
        }

        var expected = exchanges[position++];
        var actual = Convert.ToHexString(apdu);

        if (!string.Equals(actual, Convert.ToHexString(expected.Command), StringComparison.Ordinal))
        {
            throw new PivProtocolException(
                $"Exchange {position} ({expected.Label}): sent {actual}, "
                + $"transcript has {Convert.ToHexString(expected.Command)}");
        }

        var response = new byte[expected.Response.Length + 2];
        expected.Response.CopyTo(response, 0);
        response[^2] = (byte)(expected.Status >> 8);
        response[^1] = (byte)(expected.Status & 0xFF);

        return ApduResponse.Parse(response);
    }

    public IDisposable BeginTransaction() => new NoTransaction();

    public void Dispose()
    {
    }

    internal sealed record Exchange(string Label, byte[] Command, byte[] Response, ushort Status);

    private sealed record Entry(string Label, string Command, string Response, string Sw);

    private sealed class NoTransaction : IDisposable
    {
        public void Dispose()
        {
        }
    }
}
