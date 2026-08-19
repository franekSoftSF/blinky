// Blinky — PIV probe.
//
// READ-ONLY. This tool never writes to a token: no VERIFY with a real PIN, no
// key generation, no PUT DATA, no management-key authentication. It exists to
// answer one question before any production code is written — does PC/SC with
// hand-rolled PIV APDUs work on real hardware, next to whatever minidriver the
// machine already has installed?
//
// It also records an APDU transcript, which is what the Blinky.Piv unit tests
// replay (patch 0010). Pass an output path to write one:
//
//     PivProbe.exe C:\path\to\transcript.json
//
// The transcript contains certificate data and the token serial. Do not commit
// it to a public repository.

using System.Formats.Asn1;
using System.Globalization;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace Blinky.Tools.PivProbe;

internal static class Program
{
    private static readonly List<TranscriptEntry> Transcript = [];

    private static int Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        Console.WriteLine("Blinky PIV probe — read-only\n");

        var rc = NativeMethods.SCardEstablishContext(NativeMethods.ScardScopeSystem,
            IntPtr.Zero, IntPtr.Zero, out var context);
        if (rc != 0)
        {
            Console.Error.WriteLine($"SCardEstablishContext failed: 0x{rc:X8}");
            return 1;
        }

        try
        {
            var readers = ListReaders(context);
            if (readers.Count == 0)
            {
                Console.Error.WriteLine("No PC/SC readers found.");
                return 2;
            }

            Console.WriteLine($"Readers ({readers.Count}):");
            foreach (var r in readers) Console.WriteLine($"  · {r}");
            Console.WriteLine();

            var probed = 0;
            foreach (var reader in readers)
            {
                if (ProbeReader(context, reader)) probed++;
            }

            if (probed == 0)
            {
                Console.WriteLine("No reader presented a card with a PIV applet.");
                return 3;
            }

            if (args.Length > 0)
            {
                var path = args[0];
                Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
                File.WriteAllText(path, JsonSerializer.Serialize(Transcript,
                    new JsonSerializerOptions { WriteIndented = true }));
                Console.WriteLine($"\nTranscript: {path} ({Transcript.Count} exchanges)");
            }

            return 0;
        }
        finally
        {
            NativeMethods.SCardReleaseContext(context);
        }
    }

    private static bool ProbeReader(IntPtr context, string reader)
    {
        var rc = NativeMethods.SCardConnect(context, reader, NativeMethods.ScardShareShared,
            NativeMethods.ScardProtocolT0 | NativeMethods.ScardProtocolT1,
            out var card, out var protocol);

        if (rc != 0)
        {
            // No card present is the normal state of most readers on a desk.
            // Windows reports it as either NO_SMARTCARD or REMOVED_CARD.
            if ((uint)rc is not (0x8010000C or 0x80100069))
                Console.WriteLine($"[{reader}] connect failed: 0x{rc:X8} ({Describe(rc)})");
            return false;
        }

        try
        {
            var inTransaction = NativeMethods.SCardBeginTransaction(card) == 0;
            Console.WriteLine($"[{reader}]");
            Console.WriteLine($"  protocol      T={(protocol == 1 ? "0" : "1")}"
                              + $"   transaction {(inTransaction ? "acquired" : "REFUSED")}");

            try
            {
                var (_, sw) = Send(card, protocol, "SELECT PIV",
                    [0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00]);

                if (sw != 0x9000)
                {
                    Console.WriteLine($"  no PIV applet (SELECT → {sw:X4})\n");
                    return false;
                }

                ReadIdentity(card, protocol);
                ReadPinState(card, protocol);
                ReadManagementKeyState(card, protocol);
                ReadSlots(card, protocol);
                ReadAttestation(card, protocol);
                Console.WriteLine();
                return true;
            }
            finally
            {
                if (inTransaction)
                    NativeMethods.SCardEndTransaction(card, NativeMethods.ScardLeaveCard);
            }
        }
        finally
        {
            NativeMethods.SCardDisconnect(card, NativeMethods.ScardLeaveCard);
        }
    }

    private static void ReadIdentity(IntPtr card, uint protocol)
    {
        var (version, vsw) = Send(card, protocol, "GET VERSION", [0x00, 0xFD, 0x00, 0x00, 0x00]);
        var firmware = vsw == 0x9000 && version.Length == 3
            ? $"{version[0]}.{version[1]}.{version[2]}"
            : $"unavailable (SW {vsw:X4})";

        var (serialBytes, ssw) = Send(card, protocol, "GET SERIAL", [0x00, 0xF8, 0x00, 0x00, 0x00]);
        var serial = ssw == 0x9000 && serialBytes.Length == 4
            ? ((uint)((serialBytes[0] << 24) | (serialBytes[1] << 16)
                      | (serialBytes[2] << 8) | serialBytes[3])).ToString(CultureInfo.InvariantCulture)
            : $"unavailable (SW {ssw:X4})";

        Console.WriteLine($"  firmware      {firmware}");
        Console.WriteLine($"  serial        {serial}");
    }

    private static void ReadPinState(IntPtr card, uint protocol)
    {
        // VERIFY with no data returns the remaining retry count without
        // consuming one. This is the only read-only way to ask.
        var (_, sw) = Send(card, protocol, "VERIFY (empty, retry probe)", [0x00, 0x20, 0x00, 0x80]);

        var pin = (sw & 0xFFF0) == 0x63C0 ? $"{sw & 0x0F} retries left"
            : sw == 0x6983 ? "BLOCKED"
            : sw == 0x9000 ? "already verified in this session"
            : $"SW {sw:X4}";

        Console.WriteLine($"  PIN           {pin}");

        foreach (var (name, slot) in new[] { ("PIN", (byte)0x80), ("PUK", (byte)0x81) })
        {
            var (meta, msw) = Send(card, protocol, $"GET METADATA {slot:X2} ({name})",
                [0x00, 0xF7, 0x00, slot, 0x00]);
            if (msw != 0x9000)
            {
                Console.WriteLine($"  {name,-13} metadata unavailable (SW {msw:X4})"
                                  + (msw == 0x6D00 ? " — firmware < 5.3" : ""));
                continue;
            }

            var tlv = ParseSimpleTlv(meta);
            var isDefault = tlv.TryGetValue(0x05, out var d) && d.Length > 0 && d[0] == 1;
            var retries = tlv.TryGetValue(0x06, out var r) && r.Length == 2
                ? $"{r[1]}/{r[0]}" : "?";
            Console.WriteLine($"  {name,-13} default={isDefault,-5} retries={retries}");
        }
    }

    private static void ReadManagementKeyState(IntPtr card, uint protocol)
    {
        var (meta, sw) = Send(card, protocol, "GET METADATA 9B (management key)",
            [0x00, 0xF7, 0x00, 0x9B, 0x00]);

        if (sw != 0x9000)
        {
            Console.WriteLine("  mgmt key      unknown (SW " + sw.ToString("X4")
                              + (sw == 0x6D00 ? ", firmware < 5.3 — cannot be asked" : "") + ")");
            return;
        }

        var tlv = ParseSimpleTlv(meta);
        var alg = tlv.TryGetValue(0x01, out var a) && a.Length > 0
            ? a[0] switch
            {
                0x03 => "3DES", 0x08 => "AES-128", 0x0A => "AES-192", 0x0C => "AES-256",
                _ => $"0x{a[0]:X2}"
            }
            : "?";
        var isDefault = tlv.TryGetValue(0x05, out var d) && d.Length > 0 && d[0] == 1;
        var touch = tlv.TryGetValue(0x02, out var p) && p.Length == 2 && p[1] == 0x03;

        Console.WriteLine($"  mgmt key      {alg}   default={isDefault}   touch={touch}");
    }

    private static void ReadSlots(IntPtr card, uint protocol)
    {
        (string Slot, byte[] Oid)[] slots =
        [
            ("9A", [0x5F, 0xC1, 0x05]),
            ("9C", [0x5F, 0xC1, 0x0A]),
            ("9D", [0x5F, 0xC1, 0x0B]),
            ("9E", [0x5F, 0xC1, 0x01]),
        ];

        Console.WriteLine("  slots");
        foreach (var (slot, oid) in slots)
        {
            var apdu = new byte[] { 0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, oid[0], oid[1], oid[2], 0x00 };
            var (data, sw) = Send(card, protocol, $"GET DATA {slot}", apdu);

            if (sw == 0x6A82 || sw == 0x6A88)
            {
                Console.WriteLine($"    {slot}   empty");
                continue;
            }
            if (sw != 0x9000)
            {
                Console.WriteLine($"    {slot}   SW {sw:X4}");
                continue;
            }

            var cert = ExtractCertificate(data);
            if (cert is null)
            {
                Console.WriteLine($"    {slot}   {data.Length} bytes, not a certificate object");
                continue;
            }

            Console.WriteLine($"    {slot}   {Shorten(cert.Subject)}");
            Console.WriteLine($"         issuer {Shorten(cert.Issuer)}");
            Console.WriteLine($"         valid  {cert.NotBefore:yyyy-MM-dd} → {cert.NotAfter:yyyy-MM-dd}"
                              + $"   {KeyDescription(cert)}   {cert.Thumbprint[..16]}");
        }

        // Slot metadata says what the card thinks, independently of any certificate.
        foreach (var slot in new byte[] { 0x9A, 0x9C, 0x9D, 0x9E })
        {
            var (meta, sw) = Send(card, protocol, $"GET METADATA {slot:X2}",
                [0x00, 0xF7, 0x00, slot, 0x00]);
            if (sw != 0x9000) continue;

            var tlv = ParseSimpleTlv(meta);
            var alg = tlv.TryGetValue(0x01, out var a) && a.Length > 0 ? AlgorithmName(a[0]) : "?";
            var origin = tlv.TryGetValue(0x03, out var o) && o.Length > 0
                ? o[0] == 1 ? "generated" : "imported" : "?";
            var pin = "?";
            var touch = "?";
            if (tlv.TryGetValue(0x02, out var p) && p.Length == 2)
            {
                pin = p[0] switch { 1 => "never", 2 => "once", 3 => "always", _ => $"0x{p[0]:X2}" };
                touch = p[1] switch { 1 => "never", 2 => "always", 3 => "cached", _ => $"0x{p[1]:X2}" };
            }
            Console.WriteLine($"    {slot:X2}   key={alg} origin={origin} pin={pin} touch={touch}");
        }
    }

    private static void ReadAttestation(IntPtr card, uint protocol)
    {
        var (data, sw) = Send(card, protocol, "ATTEST 9A", [0x00, 0xF9, 0x9A, 0x00, 0x00]);
        if (sw != 0x9000)
        {
            Console.WriteLine($"  attestation   unavailable (SW {sw:X4})"
                              + (sw == 0x6A80 || sw == 0x6A88 ? " — no key in 9A" : ""));
            return;
        }

        X509Certificate2 cert;
        try { cert = X509CertificateLoader.LoadCertificate(data); }
        catch (Exception ex) { Console.WriteLine($"  attestation   unparseable: {ex.Message}"); return; }

        Console.WriteLine("  attestation");
        Console.WriteLine($"    issuer      {Shorten(cert.Issuer)}");

        foreach (var ext in cert.Extensions)
        {
            var label = ext.Oid?.Value switch
            {
                "1.3.6.1.4.1.41482.13.1" => "firmware",
                "1.3.6.1.4.1.41482.13.2" => "serial",
                "1.3.6.1.4.1.41482.13.3" => "policies",
                "1.3.6.1.4.1.41482.13.4" => "formfactor",
                _ => null
            };
            if (label is null) continue;

            Console.WriteLine($"    {label,-11} {Decode(label, ext.RawData)}");
        }
    }

    private static string Decode(string label, byte[] raw) => label switch
    {
        "firmware" when raw.Length == 3 => $"{raw[0]}.{raw[1]}.{raw[2]}",
        "serial" => TryDecodeInteger(raw),
        "policies" when raw.Length == 2 =>
            $"pin={raw[0] switch { 1 => "never", 2 => "once", 3 => "always", _ => "?" }} "
            + $"touch={raw[1] switch { 1 => "never", 2 => "always", 3 => "cached", _ => "?" }}",
        "formfactor" when raw.Length == 1 => $"0x{raw[0]:X2}",
        _ => Hex(raw)
    };

    private static string TryDecodeInteger(byte[] raw)
    {
        try
        {
            var reader = new AsnReader(raw, AsnEncodingRules.DER);
            return reader.ReadInteger().ToString(CultureInfo.InvariantCulture);
        }
        catch { return Hex(raw); }
    }

    private static string KeyDescription(X509Certificate2 cert)
    {
        var oid = cert.PublicKey.Oid;
        var bits = cert.PublicKey.GetRSAPublicKey()?.KeySize
                   ?? cert.PublicKey.GetECDsaPublicKey()?.KeySize;
        var name = oid.FriendlyName ?? oid.Value ?? "?";
        return bits is null ? name : $"{name}-{bits}";
    }

    private static string AlgorithmName(byte b) => b switch
    {
        0x06 => "RSA-1024", 0x07 => "RSA-2048", 0x05 => "RSA-3072", 0x16 => "RSA-4096",
        0x11 => "ECC-P256", 0x14 => "ECC-P384", 0xE0 => "Ed25519", 0xE1 => "X25519",
        _ => $"0x{b:X2}"
    };

    // ---- PIV data object → certificate -------------------------------------

    private static X509Certificate2? ExtractCertificate(byte[] data)
    {
        var outer = ParseBerTlv(data);
        if (!outer.TryGetValue(0x53, out var body)) body = data;

        var inner = ParseBerTlv(body);
        if (!inner.TryGetValue(0x70, out var der) || der.Length == 0) return null;

        // Tag 71 CertInfo: bit 0 set means the certificate is gzipped.
        if (inner.TryGetValue(0x71, out var info) && info.Length > 0 && (info[0] & 0x01) != 0)
        {
            using var input = new MemoryStream(der);
            using var gz = new GZipStream(input, CompressionMode.Decompress);
            using var output = new MemoryStream();
            gz.CopyTo(output);
            der = output.ToArray();
        }

        try { return X509CertificateLoader.LoadCertificate(der); }
        catch { return null; }
    }

    private static Dictionary<byte, byte[]> ParseBerTlv(byte[] data)
    {
        var result = new Dictionary<byte, byte[]>();
        var i = 0;
        while (i < data.Length)
        {
            var tag = data[i++];
            if (i >= data.Length) break;

            int length = data[i++];
            if (length is > 0x80 and <= 0x84)
            {
                var n = length - 0x80;
                if (i + n > data.Length) break;
                length = 0;
                for (var k = 0; k < n; k++) length = (length << 8) | data[i++];
            }
            else if (length == 0x80) break; // indefinite: not used in PIV

            if (i + length > data.Length) length = data.Length - i;
            result[tag] = data[i..(i + length)];
            i += length;
        }
        return result;
    }

    private static Dictionary<byte, byte[]> ParseSimpleTlv(byte[] data)
    {
        var result = new Dictionary<byte, byte[]>();
        var i = 0;
        while (i + 1 < data.Length)
        {
            var tag = data[i++];
            int length = data[i++];
            if (i + length > data.Length) length = data.Length - i;
            result[tag] = data[i..(i + length)];
            i += length;
        }
        return result;
    }

    // ---- transport ---------------------------------------------------------

    private static (byte[] Data, ushort Sw) Send(IntPtr card, uint protocol, string label, byte[] apdu)
    {
        var (data, sw) = Transmit(card, protocol, apdu);
        var collected = new List<byte>(data);

        // 61xx — more data available.
        while ((sw & 0xFF00) == 0x6100)
        {
            var le = (byte)(sw & 0xFF);
            var (more, nextSw) = Transmit(card, protocol, [0x00, 0xC0, 0x00, 0x00, le]);
            collected.AddRange(more);
            sw = nextSw;
        }

        Transcript.Add(new TranscriptEntry(label, Hex(apdu), Hex([.. collected]), $"{sw:X4}"));
        return ([.. collected], sw);
    }

    private static (byte[] Data, ushort Sw) Transmit(IntPtr card, uint protocol, byte[] apdu)
    {
        var pci = new NativeMethods.ScardIoRequest
        {
            Protocol = protocol,
            PciLength = (uint)Marshal.SizeOf<NativeMethods.ScardIoRequest>()
        };

        var buffer = new byte[4096];
        var received = buffer.Length;

        var rc = NativeMethods.SCardTransmit(card, ref pci, apdu, apdu.Length,
            IntPtr.Zero, buffer, ref received);

        if (rc != 0)
            throw new InvalidOperationException(
                $"SCardTransmit failed: 0x{rc:X8} ({Describe(rc)}) for {Hex(apdu)}");

        if (received < 2)
            throw new InvalidOperationException($"Short response ({received} bytes) for {Hex(apdu)}");

        var sw = (ushort)((buffer[received - 2] << 8) | buffer[received - 1]);
        return (buffer[..(received - 2)], sw);
    }

    private static List<string> ListReaders(IntPtr context)
    {
        var length = 0;
        var rc = NativeMethods.SCardListReaders(context, null, null, ref length);
        if (rc != 0 || length == 0) return [];

        var buffer = new byte[length];
        rc = NativeMethods.SCardListReaders(context, null, buffer, ref length);
        if (rc != 0) return [];

        return Encoding.ASCII.GetString(buffer, 0, length)
            .Split('\0', StringSplitOptions.RemoveEmptyEntries)
            .ToList();
    }

    private static string Describe(int rc) => (uint)rc switch
    {
        0x8010000C => "no card in reader",
        0x8010000B => "reader in exclusive use by another process",
        0x80100069 => "card removed",
        0x8010002E => "no readers available",
        0x80100017 => "reader unavailable",
        _ => "see SCARD_ error codes"
    };

    private static string Hex(byte[] data) => Convert.ToHexString(data);

    private static string Shorten(string dn) => dn.Length <= 76 ? dn : dn[..73] + "...";

    private sealed record TranscriptEntry(string Label, string Command, string Response, string Sw);
}

internal static class NativeMethods
{
    public const uint ScardScopeSystem = 2;
    public const uint ScardShareShared = 2;
    public const uint ScardProtocolT0 = 1;
    public const uint ScardProtocolT1 = 2;
    public const uint ScardLeaveCard = 0;

    [StructLayout(LayoutKind.Sequential)]
    public struct ScardIoRequest
    {
        public uint Protocol;
        public uint PciLength;
    }

    [DllImport("winscard.dll", SetLastError = true)]
    public static extern int SCardEstablishContext(uint scope, IntPtr reserved1, IntPtr reserved2,
        out IntPtr context);

    [DllImport("winscard.dll", SetLastError = true)]
    public static extern int SCardReleaseContext(IntPtr context);

    [DllImport("winscard.dll", EntryPoint = "SCardListReadersA", CharSet = CharSet.Ansi,
        SetLastError = true)]
    public static extern int SCardListReaders(IntPtr context, byte[]? groups, byte[]? readers,
        ref int readersLength);

    [DllImport("winscard.dll", EntryPoint = "SCardConnectA", CharSet = CharSet.Ansi,
        SetLastError = true)]
    public static extern int SCardConnect(IntPtr context, string reader, uint shareMode,
        uint preferredProtocols, out IntPtr card, out uint activeProtocol);

    [DllImport("winscard.dll", SetLastError = true)]
    public static extern int SCardDisconnect(IntPtr card, uint disposition);

    [DllImport("winscard.dll", SetLastError = true)]
    public static extern int SCardBeginTransaction(IntPtr card);

    [DllImport("winscard.dll", SetLastError = true)]
    public static extern int SCardEndTransaction(IntPtr card, uint disposition);

    [DllImport("winscard.dll", SetLastError = true)]
    public static extern int SCardTransmit(IntPtr card, ref ScardIoRequest sendPci,
        byte[] sendBuffer, int sendLength, IntPtr recvPci, byte[] recvBuffer, ref int recvLength);
}
