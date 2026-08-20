using System.Text;

namespace Blinky.Piv.Pcsc;

/// <summary>
/// A handle on the smart card resource manager: lists readers and connects to
/// the card in one.
/// </summary>
public sealed class PcscContext : IDisposable
{
    private IntPtr handle;
    private bool disposed;

    private PcscContext(IntPtr handle) => this.handle = handle;

    /// <summary>True when this build can talk to a reader at all.</summary>
    public static bool IsSupported => OperatingSystem.IsWindows();

    public static PcscContext Establish()
    {
        if (!IsSupported)
        {
            throw new PlatformNotSupportedException(
                "Blinky.Piv speaks to readers through winscard.dll and is Windows-only for now. "
                + "pcsc-lite support is a separate, testable piece of work - see docs/07-roadmap.md.");
        }

        PcscException.ThrowIfFailed(
            PcscInterop.SCardEstablishContext(PcscInterop.ScopeSystem, IntPtr.Zero, IntPtr.Zero,
                out var context),
            "SCardEstablishContext");

        return new PcscContext(context);
    }

    /// <summary>
    /// Every reader the service knows about, including virtual ones. Callers
    /// are expected to try the PIV applet and move on when it is not there,
    /// rather than filtering by name.
    /// </summary>
    public IReadOnlyList<string> ListReaders()
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        var length = 0;
        var probe = PcscInterop.SCardListReaders(handle, null, null, ref length);
        if (probe != 0 || length == 0)
        {
            return [];
        }

        var buffer = new byte[length];
        if (PcscInterop.SCardListReaders(handle, null, buffer, ref length) != 0)
        {
            return [];
        }

        return Encoding.ASCII.GetString(buffer, 0, length)
            .Split('\0', StringSplitOptions.RemoveEmptyEntries);
    }

    /// <summary>
    /// Connects to the card in a reader, shared rather than exclusive: exclusive
    /// mode fights the Windows smart card service and any installed minidriver,
    /// and a transaction gives the same atomicity without taking the card away
    /// from the operating system.
    /// </summary>
    /// <returns>Null when the reader is empty, which is the usual state.</returns>
    public PcscTransport? Connect(string reader)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        var code = PcscInterop.SCardConnect(handle, reader, PcscInterop.ShareShared,
            PcscInterop.ProtocolT0 | PcscInterop.ProtocolT1, out var card, out var protocol);

        if (code != 0)
        {
            var failure = new PcscException((uint)code, $"SCardConnect({reader})");
            return failure.IsNoCard ? null : throw failure;
        }

        return new PcscTransport(card, protocol, reader);
    }

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }

        disposed = true;
        if (handle != IntPtr.Zero)
        {
            PcscInterop.SCardReleaseContext(handle);
            handle = IntPtr.Zero;
        }
    }
}
