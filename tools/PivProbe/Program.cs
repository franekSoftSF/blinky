// Blinky - PIV probe.
//
// READ-ONLY. This tool never writes to a token: no VERIFY with a real PIN, no
// key generation, no PUT DATA, no management-key authentication.
//
// Everything it knows comes from Blinky.Piv - transport, chaining, the error
// map and the read path. What is left here is printing. Running this probe is
// therefore a live test of the library the agent uses, against real hardware.
//
// Pass an output path to record an APDU transcript:
//
//     PivProbe.exe C:\path\to\transcript.json
//
// Serial numbers are replaced in the transcript, so a capture can be dropped
// straight into tests/Blinky.UnitTests/Fixtures without leaking which tokens
// were on the bench.

using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Blinky.Piv;
using Blinky.Piv.Attestation;
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
            Console.Error.WriteLine(
                "Blinky.Piv talks to readers through winscard.dll; this build is Windows-only.");
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

        var probed = readers.Count(reader => ProbeReader(context, reader));

        if (probed == 0)
        {
            Console.WriteLine("No reader presented a card with a PIV applet.");
            return 3;
        }

        if (args.Length > 0)
        {
            WriteTranscript(args[0]);
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

        // Record at the transport, so the transcript holds the raw exchanges -
        // including any GET RESPONSE the chaining logic issues by itself.
        using var recorder = new RecordingTransport(card, Transcript, () => currentLabel);
        using var connection = new PivConnection(recorder);
        var session = new PivSession(connection);

        Console.WriteLine($"[{reader}]");

        try
        {
            using var transaction = connection.BeginTransaction();
            Console.WriteLine($"  protocol      {card.Protocol}   transaction acquired");

            currentLabel = "SELECT PIV";
            if (!session.Select())
            {
                Console.WriteLine("  no PIV applet\n");
                return false;
            }

            Print(session, recorder);
            Console.WriteLine();
            return true;
        }
        catch (PcscException ex)
        {
            Console.WriteLine($"  {ex.Message}\n");
            return false;
        }
        catch (PivException ex)
        {
            Console.WriteLine($"  {ex.Message}\n");
            return false;
        }
    }

    private static void Print(PivSession session, RecordingTransport recorder)
    {
        currentLabel = "inventory";
        var token = session.ReadInventory();

        Console.WriteLine($"  firmware      {Describe(token.Firmware)}");
        Console.WriteLine("  serial        "
                          + (token.SerialNumber?.ToString(CultureInfo.InvariantCulture)
                             ?? "unavailable"));
        Console.WriteLine($"  PIN           {Describe(token.Pin)}");
        Console.WriteLine($"  PUK           {Describe(token.Puk)}");
        Console.WriteLine($"  mgmt key      {Describe(token.ManagementKey)}");
        Console.WriteLine($"  biometrics    {Describe(token.Biometrics)}");

        Console.WriteLine("  slots");
        foreach (var slot in token.Slots)
        {
            Console.WriteLine($"    {slot.Slot}   {Describe(slot)}");

            if (slot.CertificateDer is not null)
            {
                PrintCertificate(slot.CertificateDer);
            }
        }

        PrintAttestation(session, recorder);
    }

    private static string Describe(FirmwareVersion firmware) =>
        firmware == FirmwareVersion.Unknown ? "unavailable" : firmware.ToString();

    private static string Describe(PinMetadata credential)
    {
        if (credential.State is PinState.NotConfigured)
        {
            return "NOT CONFIGURED - no PUK on this token; a blocked PIN can only be "
                   + "resolved by a full reset";
        }

        var retries = credential switch
        {
            { RemainingRetries: { } remaining, TotalRetries: { } total } => $"{remaining}/{total}",
            { RemainingRetries: { } remaining } => remaining.ToString(CultureInfo.InvariantCulture),
            _ => "?",
        };

        return $"{credential.State,-8} retries={retries}";
    }

    private static string Describe(ManagementKeyMetadata? key) => key is null
        ? "unknown - firmware cannot be asked"
        : $"{key.Algorithm}   default={key.IsDefault}   touch={key.TouchPolicy}";

    private static string Describe(BiometricMetadata? biometrics) => biometrics is null
        ? "not supported"
        : "SUPPORTED   enrolled=" + biometrics.FingerprintsEnrolled
          + "   attempts="
          + (biometrics.AttemptsRemaining?.ToString(CultureInfo.InvariantCulture) ?? "?")
          + "   temporary PIN=" + biometrics.TemporaryPinSet;

    private static string Describe(SlotInventory slot)
    {
        if (slot.IsEmpty)
        {
            return "empty";
        }

        var metadata = slot.Metadata is null
            ? "key present"
            : $"key={slot.Metadata.Algorithm} origin={slot.Metadata.Origin} "
              + $"pin={slot.Metadata.PinPolicy} touch={slot.Metadata.TouchPolicy}";

        return slot.HasCertificate ? $"{metadata}, certificate" : $"{metadata}, no certificate";
    }

    private static void PrintCertificate(byte[] der)
    {
        X509Certificate2 certificate;
        try
        {
            certificate = X509CertificateLoader.LoadCertificate(der);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"         {der.Length} bytes, not a certificate: {ex.Message}");
            return;
        }

        Console.WriteLine($"         subject {Shorten(certificate.Subject)}");
        Console.WriteLine($"         issuer  {Shorten(certificate.Issuer)}");
        Console.WriteLine($"         valid   {certificate.NotBefore:yyyy-MM-dd} to "
                          + $"{certificate.NotAfter:yyyy-MM-dd}   {KeyDescription(certificate)}   "
                          + $"{certificate.Thumbprint[..16]}");
    }

    /// <summary>
    /// Reads the attestation for slot 9A and verifies it against the pinned
    /// Yubico root. This is the part a synthetic PKI cannot prove: the unit
    /// tests show the verifier rejects forgeries, and this shows it accepts a
    /// real token.
    /// </summary>
    private static void PrintAttestation(PivSession session, RecordingTransport recorder)
    {
        // An attestation certificate names the device: the real serial sits in
        // extension 1.3.6.1.4.1.41482.3.7 and the certificate is unique to one
        // token. Nothing about it goes into a transcript that might be
        // committed, so recording stops here rather than being filtered later.
        recorder.Paused = true;

        try
        {
            var leaf = session.Attest(PivSlot.Authentication);
            if (leaf is null)
            {
                Console.WriteLine("  attestation   no key in 9A, nothing to attest");
                return;
            }

            var intermediate = session.GetAttestationCertificate();
            if (intermediate is null)
            {
                Console.WriteLine("  attestation   slot F9 is empty - cannot build a chain");
                return;
            }

            var serial = session.GetSerialNumber();
            var verifier = new AttestationVerifier(YubicoRoots.PivAttestation);
            var result = verifier.Verify(leaf, intermediate, PivSlot.Authentication, serial);

            Console.WriteLine($"  attestation   {result}");
            Console.WriteLine($"    intermediate {Shorten(intermediate.Subject)}");
            Console.WriteLine($"    issued by    {Shorten(intermediate.Issuer)}");

            if (result.Attestation is { } attestation)
            {
                Console.WriteLine($"    firmware     {attestation.Firmware}");
                Console.WriteLine($"    device       {attestation.SerialNumber}"
                                  + $"   {attestation.FormFactor}"
                                  + (attestation.IsFipsDevice ? "   FIPS" : string.Empty));
                Console.WriteLine($"    key policy   pin={attestation.PinPolicy} "
                                  + $"touch={attestation.TouchPolicy}");
            }
        }
        catch (PivException ex)
        {
            Console.WriteLine($"  attestation   {ex.Message}");
        }
        finally
        {
            recorder.Paused = false;
        }
    }

    private static string KeyDescription(X509Certificate2 certificate)
    {
        var oid = certificate.PublicKey.Oid;
        var bits = certificate.PublicKey.GetRSAPublicKey()?.KeySize
                   ?? certificate.PublicKey.GetECDsaPublicKey()?.KeySize;
        var name = oid.FriendlyName ?? oid.Value ?? "?";

        return bits is null ? name : $"{name}-{bits}";
    }

    private static string Shorten(string dn) => dn.Length <= 76 ? dn : dn[..73] + "...";

    /// <summary>
    /// Writes the transcript with serial numbers replaced. The redaction is
    /// here rather than in a separate step so that a capture is safe to commit
    /// by construction - the console still shows the real serial.
    /// </summary>
    private static void WriteTranscript(string path)
    {
        const string getSerialCommand = "00F8000000";
        var replacements = new Dictionary<string, string>(StringComparer.Ordinal);

        var redacted = Transcript.Select(entry =>
        {
            if (entry.Command != getSerialCommand || entry.Sw != "9000" || entry.Response.Length == 0)
            {
                return entry;
            }

            if (!replacements.TryGetValue(entry.Response, out var fake))
            {
                fake = $"00BADA{0x55 + replacements.Count:X2}";
                replacements[entry.Response] = fake;
            }

            return entry with { Response = fake };
        }).ToList();

        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        File.WriteAllText(path, JsonSerializer.Serialize(redacted,
            new JsonSerializerOptions { WriteIndented = true }));

        Console.WriteLine($"\nTranscript: {path} ({redacted.Count} exchanges, "
                          + $"{replacements.Count} serials redacted)");
    }
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

    /// <summary>
    /// While set, exchanges are not written down at all. Used around
    /// attestation: filtering it out afterwards missed the GET RESPONSE
    /// continuations and leaked two thirds of the certificate into a fixture.
    /// Not recording it cannot half-work.
    /// </summary>
    public bool Paused { get; set; }

    public ApduResponse Transmit(ReadOnlySpan<byte> apdu)
    {
        var command = Convert.ToHexString(apdu);
        var response = inner.Transmit(apdu);

        if (!Paused)
        {
            transcript.Add(new TranscriptEntry(label(), command,
                Convert.ToHexString(response.Data), response.Status.ToString()));
        }

        return response;
    }

    public IDisposable BeginTransaction() => inner.BeginTransaction();

    public void Dispose() => inner.Dispose();
}

internal sealed record TranscriptEntry(string Label, string Command, string Response, string Sw);
