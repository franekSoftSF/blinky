// Blinky - PIV probe.
//
// READ-ONLY. This tool never writes to a token: no VERIFY with a real PIN, no
// key generation, no PUT DATA, no management-key authentication. It exists to
// exercise Blinky.Piv against real hardware and to report what is on a card.
//
// The transport, command chaining and error mapping all come from Blinky.Piv,
// so running this probe is a live test of the same code the agent uses. What
// stays here is the parsing and the printing - the read path proper is patch
// 0011.
//
// Pass an output path to record an APDU transcript:
//
//     PivProbe.exe C:\path\to\transcript.json
//
// The transcript contains the token serial and any certificate on the card.
// Do not commit it to a public repository - the fixture under
// tests/Blinky.UnitTests/Fixtures is a redacted copy.

using System.Formats.Asn1;
using System.Globalization;
using System.IO.Compression;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Blinky.Piv;
using Blinky.Piv.Pcsc;

namespace Blinky.Tools.PivProbe;

internal static class Program
{
    private static readonly List<TranscriptEntry> Transcript = [];
    private static string currentLabel = "?";

    private static int Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        Console.WriteLine("Blinky PIV probe - read-only\n");

        if (!PcscContext.IsSupported)
        {
            Console.Error.WriteLine("Blinky.Piv talks to readers through winscard.dll; "
                                    + "this build is Windows-only.");
            return 4;
        }

        using var context = PcscContext.Establish();

        var readers = context.ListReaders();
        if (readers.Count == 0)
        {
            Console.Error.WriteLine("No PC/SC readers found.");
            return 2;
        }

        Console.WriteLine($"Readers ({readers.Count}):");
        foreach (var reader in readers)
        {
            Console.WriteLine($"  - {reader}");
        }

        Console.WriteLine();

        var probed = 0;
        foreach (var reader in readers)
        {
            if (ProbeReader(context, reader))
            {
                probed++;
            }
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

    private static bool ProbeReader(PcscContext context, string reader)
    {
        PcscTransport? card;
        try
        {
            card = context.Connect(reader);
        }
        catch (PcscException ex)
        {
            Console.WriteLine($"[{reader}] {ex.Message}");
            return false;
        }

        // An empty reader is the usual state of most readers on a desk.
        if (card is null)
        {
            return false;
        }

        // Record at the transport, not above it: a transcript of the raw
        // exchanges is what the replay tests need, including any GET RESPONSE
        // the chaining logic issues on its own.
        using var recorder = new RecordingTransport(card, Transcript, () => currentLabel);
        using var connection = new PivConnection(recorder);

        Console.WriteLine($"[{reader}]");

        try
        {
            using var transaction = connection.BeginTransaction();
            Console.WriteLine($"  protocol      {card.Protocol}   transaction acquired");

            currentLabel = "SELECT PIV";
            if (!connection.SelectPiv())
            {
                Console.WriteLine("  no PIV applet\n");
                return false;
            }

            ReadIdentity(connection);
            ReadPinState(connection);
            ReadManagementKeyState(connection);
            ReadBiometricState(connection);
            ReadSlots(connection);
            ReadAttestation(connection);
            Console.WriteLine();
            return true;
        }
        catch (PcscException ex)
        {
            Console.WriteLine($"  {ex.Message}\n");
            return false;
        }
    }

    private static void ReadIdentity(PivConnection connection)
    {
        var (version, vsw) = Send(connection, "GET VERSION", [0x00, 0xFD, 0x00, 0x00, 0x00]);
        var firmware = vsw == 0x9000 && version.Length == 3
            ? $"{version[0]}.{version[1]}.{version[2]}"
            : $"unavailable (SW {vsw:X4})";

        var (serialBytes, ssw) = Send(connection, "GET SERIAL", [0x00, 0xF8, 0x00, 0x00, 0x00]);
        var serial = ssw == 0x9000 && serialBytes.Length == 4
            ? ((uint)((serialBytes[0] << 24) | (serialBytes[1] << 16)
                      | (serialBytes[2] << 8) | serialBytes[3])).ToString(CultureInfo.InvariantCulture)
            : $"unavailable (SW {ssw:X4})";

        Console.WriteLine($"  firmware      {firmware}");
        Console.WriteLine($"  serial        {serial}");
    }

    private static void ReadPinState(PivConnection connection)
    {
        // VERIFY with no data returns the remaining retry count without
        // consuming one. This is the only read-only way to ask.
        var (_, sw) = Send(connection, "VERIFY (empty, retry probe)", [0x00, 0x20, 0x00, 0x80]);

        var pin = (sw & 0xFFF0) == 0x63C0 ? $"{sw & 0x0F} retries left"
            : sw == 0x6983 ? "BLOCKED"
            : sw == 0x9000 ? "already verified in this session"
            : $"SW {sw:X4}";

        Console.WriteLine($"  PIN           {pin}");

        foreach (var (name, slot) in new[] { ("PIN", (byte)0x80), ("PUK", (byte)0x81) })
        {
            var (meta, msw) = Send(connection, $"GET METADATA {slot:X2} ({name})",
                [0x00, 0xF7, 0x00, slot, 0x00]);
            if (msw != 0x9000)
            {
                Console.WriteLine($"  {name,-13} metadata unavailable (SW {msw:X4})"
                                  + (msw == 0x6D00 ? " — firmware < 5.3" : ""));
                continue;
            }

            var tlv = ParseSimpleTlv(meta);
            var isDefault = tlv.TryGetValue(0x05, out var d) && d.Length > 0 && d[0] == 1;
            var hasRetries = tlv.TryGetValue(0x06, out var r) && r.Length == 2;

            // Firmware 5.7 can delete the PUK outright. Total retries of zero
            // means there is no PUK to unblock the PIN with, and the only
            // recovery left is a full PIV reset - which destroys every key.
            if (name == "PUK" && hasRetries && r![0] == 0)
            {
                Console.WriteLine($"  {name,-13} NOT CONFIGURED - deleted or blocked; "
                                  + "PIN unblock is impossible on this token");
                continue;
            }

            var retries = hasRetries ? $"{r![1]}/{r[0]}" : "?";
            Console.WriteLine($"  {name,-13} default={isDefault,-5} retries={retries}");
        }
    }

    private static void ReadManagementKeyState(PivConnection connection)
    {
        var (meta, sw) = Send(connection, "GET METADATA 9B (management key)",
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

    private static void ReadBiometricState(PivConnection connection)
    {
        // Slot 96 is on-card biometric comparison (SP 800-73-4 OCC). Present
        // only on the Bio Multi-protocol Edition; everything else answers with
        // an error, which is the detection.
        var (meta, sw) = Send(connection, "GET METADATA 96 (biometric)",
            [0x00, 0xF7, 0x00, 0x96, 0x00]);

        if (sw != 0x9000)
        {
            Console.WriteLine($"  biometrics    not supported (SW {sw:X4})");
            return;
        }

        // Print the raw TLV as well as the decode: this is a less-travelled
        // corner of the applet and the bytes are the evidence.
        Console.WriteLine($"  biometrics    SUPPORTED   raw={Hex(meta)}");

        var tlv = ParseSimpleTlv(meta);
        foreach (var (tag, value) in tlv.OrderBy(kv => kv.Key))
        {
            var label = tag switch
            {
                0x06 => "attempts remaining",
                0x07 => "fingerprints enrolled",
                0x08 => "temporary PIN set",
                _ => $"tag {tag:X2}"
            };
            var decoded = value.Length == 1 && tag is 0x07 or 0x08
                ? value[0] == 1 ? "yes" : "no"
                : value.Length == 1 ? value[0].ToString(CultureInfo.InvariantCulture)
                : Hex(value);
            Console.WriteLine($"    {label,-22} {decoded}");
        }

        var (_, vsw) = Send(connection, "VERIFY 96 (empty, bio attempt probe)",
            [0x00, 0x20, 0x00, 0x96]);
        var attempts = (vsw & 0xFFF0) == 0x63C0 ? $"{vsw & 0x0F} match attempts left"
            : vsw == 0x6983 ? "BLOCKED - falls back to PIN"
            : $"SW {vsw:X4}";
        Console.WriteLine($"    attempts   {attempts}");
    }

    private static void ReadSlots(PivConnection connection)
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
            var (data, sw) = Send(connection, $"GET DATA {slot}", apdu);

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
            var (meta, sw) = Send(connection, $"GET METADATA {slot:X2}",
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

    private static void ReadAttestation(PivConnection connection)
    {
        var (data, sw) = Send(connection, "ATTEST 9A", [0x00, 0xF9, 0x9A, 0x00, 0x00]);
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

    /// <summary>
    /// Sends a literal APDU and returns its data and status word, keeping the
    /// call sites below readable as the raw commands they are. Chaining, GET
    /// RESPONSE and 6Cxx are handled inside Blinky.Piv.
    /// </summary>
    private static (byte[] Data, ushort Sw) Send(PivConnection connection, string label, byte[] apdu)
    {
        currentLabel = label;
        var response = connection.Send(Decode(apdu));
        return (response.Data, response.Status.Value);
    }

    private static ApduCommand Decode(byte[] apdu)
    {
        var (cla, ins, p1, p2) = (apdu[0], apdu[1], apdu[2], apdu[3]);

        if (apdu.Length == 4)
        {
            return new ApduCommand(ins, p1, p2, cla: cla);
        }

        if (apdu.Length == 5)
        {
            return new ApduCommand(ins, p1, p2, le: apdu[4], cla: cla);
        }

        var lc = apdu[4];
        var hasLe = apdu.Length == 5 + lc + 1;

        return new ApduCommand(ins, p1, p2, apdu.AsMemory(5, lc), hasLe ? apdu[^1] : null, cla);
    }

    private static string Hex(byte[] data) => Convert.ToHexString(data);

    private static string Shorten(string dn) => dn.Length <= 76 ? dn : dn[..73] + "...";

}


/// <summary>
/// Wraps a transport and writes down every exchange, so a probe run produces a
/// fixture the unit tests can replay.
/// </summary>
internal sealed class RecordingTransport(
    IApduTransport inner,
    List<TranscriptEntry> transcript,
    Func<string> label) : IApduTransport
{
    public string Description => inner.Description;

    public ApduResponse Transmit(ReadOnlySpan<byte> apdu)
    {
        var command = Convert.ToHexString(apdu);
        var response = inner.Transmit(apdu);

        transcript.Add(new TranscriptEntry(label(), command,
            Convert.ToHexString(response.Data), response.Status.ToString()));

        return response;
    }

    public IDisposable BeginTransaction() => inner.BeginTransaction();

    public void Dispose() => inner.Dispose();
}

internal sealed record TranscriptEntry(string Label, string Command, string Response, string Sw);
