using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Blinky.Contracts;
using Blinky.Piv;
using Blinky.Piv.Attestation;
using Blinky.Piv.Pcsc;

namespace Blinky.Agent.Service;

/// <summary>
/// Puts a credential onto a token: generate, attest, sign, issue, write back.
/// </summary>
/// <remarks>
/// <para>
/// One job step rather than eight, and that is a correction to doc 05. Every
/// phase here shares a single PC/SC transaction and the security state that
/// goes with it — a verified PIN and an authenticated management key are lost
/// the moment the card is released. Phases that the server scheduled
/// separately would each have to re-authenticate, and the PIN would have to be
/// asked for again or kept somewhere. Neither is acceptable, so the phases are
/// <b>reported</b> rather than scheduled.
/// </para>
/// <para>
/// The diagnostic value survives: a failure still names the phase it happened
/// in, which is the thing that mattered about granular steps.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class CardEnrolment(
    UserPrompts prompts,
    ILogger<CardEnrolment> logger) : ICardEnrolment
{
    private readonly AttestationVerifier verifier = new(YubicoRoots.PivAttestation);

    public async Task EnrolAsync(JobEnvelope job, JobStep step, BackendClient backend,
        int attempt, CancellationToken ct)
    {
        var serial = job.TokenSerial
                     ?? throw new InvalidOperationException("An enrolment names its token.");

        var slotName = step.Argument("slot") ?? "9A";
        var profile = step.Argument("profile") ?? "smartcard-logon";

        var slot = PivSlot.Credentials.FirstOrDefault(s =>
            s.Name.Equals(slotName, StringComparison.OrdinalIgnoreCase));

        if (slot.Id == 0)
        {
            throw new InvalidOperationException($"{slotName} is not a credential slot.");
        }

        using var context = PcscContext.Establish();

        foreach (var reader in context.ListReaders())
        {
            using var card = context.Connect(reader);
            if (card is null)
            {
                continue;
            }

            using var connection = new PivConnection(card, ownsTransport: false);
            var session = new PivSession(connection);

            // One transaction for the whole enrolment. Releasing the card
            // between phases would drop the verified PIN with it.
            using var transaction = connection.BeginTransaction();

            if (!session.Select() || session.GetSerialNumber() != (uint)serial)
            {
                continue;
            }

            await RunAsync(session, slot, profile, serial, job, backend, attempt, ct);
            return;
        }

        throw new InvalidOperationException(
            $"Token {serial} is not in any reader on this machine.");
    }

    private async Task RunAsync(PivSession session, PivSlot slot, string profileName,
        long serial, JobEnvelope job, BackendClient backend, int attempt, CancellationToken ct)
    {
        await Report(backend, job, attempt, "AuthenticateManagementKey", ct);

        var management = session.GetManagementKeyMetadata()
            ?? throw new InvalidOperationException(
                "This firmware will not say which management key algorithm it holds.");

        // The factory key, because personalisation is patch 0025. Once that
        // lands this becomes the derived value and a token still holding the
        // factory key is refused instead.
        session.AuthenticateManagementKey(ManagementKey.Default(management.Algorithm));

        await Report(backend, job, attempt, "GenerateKey", ct);

        var existing = session.GetSlotMetadata(slot);
        if (existing is not null)
        {
            // Generating destroys what is there, with no copy anywhere. The
            // server decided this slot was free; if it is not, that assumption
            // is wrong and the job stops rather than the key.
            throw new InvalidOperationException(
                $"Slot {slot} already holds a {existing.Algorithm} key. Refusing to destroy it.");
        }

        var generated = session.GenerateKeyPair(slot, PivAlgorithm.EccP256,
            PinPolicy.Once, TouchPolicy.Never);

        await Report(backend, job, attempt, "Attest", ct);

        var leaf = session.Attest(slot)
                   ?? throw new InvalidOperationException("The token attested to nothing.");
        var intermediate = session.GetAttestationCertificate()
                           ?? throw new InvalidOperationException("Slot F9 is empty.");

        var local = verifier.Verify(leaf, intermediate, slot, (uint)serial,
            generated.SubjectPublicKeyInfo);

        if (!local.IsTrusted)
        {
            // Checked here as well as on the server, so a bad token fails
            // before a person is asked for a PIN.
            throw new InvalidOperationException($"Attestation refused locally: {local}");
        }

        await Report(backend, job, attempt, "VerifyUser", ct,
            JobState.AwaitingUser, "waiting for the PIN");

        var pin = await prompts.AskForPinAsync(serial, session.GetPinMetadata().RemainingRetries,
            "Blinky is issuing a certificate onto your key.", ct);

        if (pin is null)
        {
            throw new InvalidOperationException("Nobody entered a PIN.");
        }

        session.VerifyPin(pin);

        await Report(backend, job, attempt, "BuildAndSignCsr", ct);

        var generator = new PivSignatureGenerator(session, slot, generated);
        var request = new CertificateRequest(
            new X500DistinguishedName($"CN={step_DisplayName(job)}"),
            generator.PublicKey, HashAlgorithmName.SHA256);

        var csrPem = PemEncode("CERTIFICATE REQUEST", request.CreateSigningRequest(generator));

        await Report(backend, job, attempt, "SubmitToCa", ct);

        var issued = await backend.IssueCredentialAsync(new IssueCredentialRequest(
            Protocol.SchemaVersion, serial, slot.Name, profileName, csrPem,
            leaf.ExportCertificatePem(), intermediate.ExportCertificatePem(),
            CardholderFrom(job)), ct);

        await Report(backend, job, attempt, "WriteCertificate", ct);

        using var certificate = X509Certificate2.CreateFromPem(issued.CertificatePem);
        session.PutCertificate(slot, certificate.RawData);

        // Read back before saying it is installed. A 9000 means the card took
        // the write, not that what came back is what went in.
        var readBack = session.GetCertificateAsX509(slot)
                       ?? throw new InvalidOperationException(
                           $"Slot {slot} reads back empty after the write.");

        if (readBack.Thumbprint != certificate.Thumbprint)
        {
            throw new InvalidOperationException(
                $"Slot {slot} holds a different certificate than the one written.");
        }

        await backend.ConfirmInstalledAsync(
            new CredentialInstalled(issued.CredentialId, readBack.Thumbprint), ct);

        logger.LogInformation("Token {Serial} slot {Slot} now holds {Subject}, issued by {Issuer}",
            serial, slot, readBack.Subject, issued.IssuerSubject);
    }

    private static string step_DisplayName(JobEnvelope job) =>
        job.Steps.FirstOrDefault()?.Argument("displayName") ?? "Blinky cardholder";

    private static CardholderRequest CardholderFrom(JobEnvelope job)
    {
        var step = job.Steps.FirstOrDefault();

        return new CardholderRequest(
            step?.Argument("displayName") ?? "Blinky cardholder",
            step?.Argument("upn"),
            step?.Argument("objectSid"));
    }

    private static Task Report(BackendClient backend, JobEnvelope job, int attempt,
        string phase, CancellationToken ct, JobState state = JobState.Running,
        string? detail = null) =>
        backend.ReportProgressAsync(new JobProgress(job.JobId, attempt, state, phase, detail), ct);

    private static string PemEncode(string label, byte[] der) =>
        $"-----BEGIN {label}-----\n"
        + Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks)
        + $"\n-----END {label}-----\n";
}
