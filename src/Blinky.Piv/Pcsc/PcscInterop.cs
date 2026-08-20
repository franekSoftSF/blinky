using System.Runtime.InteropServices;

namespace Blinky.Piv.Pcsc;

/// <summary>
/// P/Invoke into the Windows smart card resource manager.
/// </summary>
/// <remarks>
/// Windows only, on purpose. pcsc-lite is not simply the same entry points
/// under another library name: its DWORD is register-width, so SCARD_IO_REQUEST
/// and every length parameter marshal differently, and there is no reader on
/// this bench to test that against. Shipping untested marshalling in the layer
/// everything else depends on would be worse than a named gap - see the
/// roadmap.
/// </remarks>
internal static partial class PcscInterop
{
    private const string Library = "winscard.dll";

    internal const uint ScopeSystem = 2;
    internal const uint ShareShared = 2;
    internal const uint ProtocolT0 = 1;
    internal const uint ProtocolT1 = 2;
    internal const uint LeaveCard = 0;

    [StructLayout(LayoutKind.Sequential)]
    internal struct ScardIoRequest
    {
        public uint Protocol;
        public uint PciLength;
    }

    [LibraryImport(Library, EntryPoint = "SCardEstablishContext")]
    internal static partial int SCardEstablishContext(uint scope, IntPtr reserved1,
        IntPtr reserved2, out IntPtr context);

    [LibraryImport(Library, EntryPoint = "SCardReleaseContext")]
    internal static partial int SCardReleaseContext(IntPtr context);

    [LibraryImport(Library, EntryPoint = "SCardIsValidContext")]
    internal static partial int SCardIsValidContext(IntPtr context);

    [LibraryImport(Library, EntryPoint = "SCardListReadersA")]
    internal static partial int SCardListReaders(IntPtr context, byte[]? groups,
        byte[]? readers, ref int readersLength);

    [LibraryImport(Library, EntryPoint = "SCardConnectA", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int SCardConnect(IntPtr context, string reader, uint shareMode,
        uint preferredProtocols, out IntPtr card, out uint activeProtocol);

    [LibraryImport(Library, EntryPoint = "SCardDisconnect")]
    internal static partial int SCardDisconnect(IntPtr card, uint disposition);

    [LibraryImport(Library, EntryPoint = "SCardBeginTransaction")]
    internal static partial int SCardBeginTransaction(IntPtr card);

    [LibraryImport(Library, EntryPoint = "SCardEndTransaction")]
    internal static partial int SCardEndTransaction(IntPtr card, uint disposition);

    [LibraryImport(Library, EntryPoint = "SCardTransmit")]
    internal static partial int SCardTransmit(IntPtr card, ref ScardIoRequest sendPci,
        byte[] sendBuffer, int sendLength, IntPtr recvPci, byte[] recvBuffer,
        ref int recvLength);
}
