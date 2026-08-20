using System.Runtime.InteropServices;

namespace Blinky.Piv.Pcsc;

/// <summary>One connected card. Transmits APDUs and nothing more.</summary>
public sealed class PcscTransport : IApduTransport
{
    private const int ResponseBufferSize = 4096;

    private readonly uint protocol;
    private IntPtr card;
    private bool disposed;

    internal PcscTransport(IntPtr card, uint protocol, string reader)
    {
        this.card = card;
        this.protocol = protocol;
        Description = reader;
    }

    public string Description { get; }

    /// <summary>T=0 or T=1, whichever the card and reader negotiated.</summary>
    public string Protocol => protocol == PcscInterop.ProtocolT0 ? "T=0" : "T=1";

    public ApduResponse Transmit(ReadOnlySpan<byte> apdu)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        var request = new PcscInterop.ScardIoRequest
        {
            Protocol = protocol,
            PciLength = (uint)Marshal.SizeOf<PcscInterop.ScardIoRequest>(),
        };

        var buffer = new byte[ResponseBufferSize];
        var received = buffer.Length;
        var command = apdu.ToArray();

        PcscException.ThrowIfFailed(
            PcscInterop.SCardTransmit(card, ref request, command, command.Length, IntPtr.Zero,
                buffer, ref received),
            $"SCardTransmit({Convert.ToHexString(command)})");

        if (received < 2)
        {
            throw new PivProtocolException(
                $"The card returned {received} bytes, too few to contain a status word.");
        }

        return ApduResponse.Parse(buffer.AsSpan(0, received));
    }

    /// <summary>
    /// Holds the card for a sequence of commands. Not exclusive access - other
    /// processes wait rather than fail, which is what keeps this working next to
    /// a minidriver.
    /// </summary>
    public IDisposable BeginTransaction()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        PcscException.ThrowIfFailed(PcscInterop.SCardBeginTransaction(card), "SCardBeginTransaction");
        return new Transaction(this);
    }

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }

        disposed = true;
        if (card != IntPtr.Zero)
        {
            PcscInterop.SCardDisconnect(card, PcscInterop.LeaveCard);
            card = IntPtr.Zero;
        }
    }

    private sealed class Transaction(PcscTransport owner) : IDisposable
    {
        private bool ended;

        public void Dispose()
        {
            if (ended || owner.disposed)
            {
                return;
            }

            ended = true;
            PcscInterop.SCardEndTransaction(owner.card, PcscInterop.LeaveCard);
        }
    }
}
