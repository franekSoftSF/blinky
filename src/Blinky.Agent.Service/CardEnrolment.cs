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
    CardGate gate,
    ILogger<CardEnrolment> logger) : ICardEnrolment
{
    private readonly AttestationVerifier verifier = new(YubicoRoots.PivAttestation);

    public async Task EnrolAsync(JobEnvelope job, JobStep step, BackendClient backend,
        int attempt, CancellationToken ct)
    {
        var serial = job.TokenSerial
                     ?? throw new InvalidOperationException("An enrolment names its token.");

        var slotName = step.Argument("slot") ?? "9A";
        var algorithm = ParseAlgorithm(step.Argument("keyAlgorithm"));
        var replaceKey = step.Argument("replaceKey") == "true";
        var profile = step.Argument("profile") ?? "smartcard-logon";

        var slot = PivSlot.Credentials.FirstOrDefault(s =>
            s.Name.Equals(slotName, StringComparison.OrdinalIgnoreCase));

        if (slot.Id == 0)
        {
            throw new InvalidOperationException($"{slotName} is not a credential slot.");
        }

        // Held for the whole enrolment, prompt included. A sweep or a tray
        // click landing in the middle would take the reader and lose the
        // verified PIN with it.
        using var held = await gate.AcquireAsync(ct);

        using var context = PcscContext.Establish();

        foreach (var reader in context.ListReaders())
        {
            using var card = context.Connect(reader);
            if (card is null)
            {
                continue;
            }

            // One transaction for the whole enrolment. Releasing the card
            // between phases would drop the verified PIN with it.
            PivSession session;
            PivConnection connection;
            IDisposable transaction;

            try
            {
                connection = new PivConnection(card, ownsTransport: false);
                session = new PivSession(connection);
                transaction = connection.BeginTransaction();

                if (!session.Select() || session.GetSerialNumber() != (uint)serial)
                {
                    transaction.Dispose();
                    connection.Dispose();
                    continue;
                }
            }
            catch (Exception ex) when (ex is PcscException or PivException or PivProtocolException)
            {
                // One reader that will not answer must not end an operation
                // aimed at a token in a different one. Seen on this bench: an
                // OMNIKEY 5022 returned 0x80100066 and took down an enrolment
                // meant for a YubiKey two readers along, in three tenths of a
                // second and with the reader's name nowhere near the failure
                // an operator would read.
                logger.LogWarning("Reader {Reader} could not be used: {Message}",
                    reader, ex.Message);

                continue;
            }

            using (connection)
            using (transaction)
            {
                await RunAsync(session, slot, profile, algorithm, replaceKey,
                    serial, job, backend, attempt, ct);
            }

            return;
        }

        throw new InvalidOperationException(
            $"Token {serial} is not in any reader on this machine.");
    }

    private async Task RunAsync(PivSession session, PivSlot slot, string profileName,
        PivAlgorithm algorithm, bool replaceKey,
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

        // Before anything else is written, because a certificate on a card
        // with no CHUID is a certificate Windows can see and cannot use: the
        // inbox minidriver enumerates key containers from the CCC and
        // identifies the card by the CHUID's GUID, and without them it answers
        // NTE_BAD_KEYSET for a key that is sitting right there. A YubiKey
        // leaves the factory without either, and `ykman piv reset` removes
        // them again.
        //
        // Costs nothing on a card that already has them - they are read first
        // and left alone, because the GUID is how the operating system tells
        // one card from another and replacing it would make an enrolled card
        // look like a new one.
        var identity = session.EnsureCardIdentity(
            DateOnly.FromDateTime(DateTime.UtcNow.AddYears(10)));

        if (identity.Anything)
        {
            logger.LogInformation(
                "Token {Serial}: wrote {What} - the card had none, and Windows needs "
                + "them to find a key container at all", serial, identity);
        }

        await Report(backend, job, attempt, "GenerateKey", ct);

        var existing = session.GetSlotMetadata(slot);
        if (existing is not null && replaceKey)
        {
            // Generating destroys what is there. Allowed here because the
            // server said so, and it says so only for a key it put in this
            // slot itself and has since revoked.
            //
            // That case is not rare and has no other way out. Recycling a
            // credential deletes the certificate, and on some firmware the key
            // will not delete with it - YubiKey 5.4.3 answers 6D00 to
            // DeleteKey. The slot is then left holding a key belonging to
            // nothing, and a refusal to overwrite it means the slot can never
            // be used again: every later enrolment stops on a key the operator
            // already asked to have removed.
            logger.LogInformation(
                "Token {Serial} slot {Slot}: generating over an orphaned {Algorithm} key, "
                + "which the server revoked and the card would not delete",
                serial, slot, existing.Algorithm);
        }
        else if (existing is not null)
        {
            // Generating destroys what is there, with no copy anywhere. The
            // server decided this slot was free; if it is not, that assumption
            // is wrong and the job stops rather than the key.
            throw new InvalidOperationException(
                $"Slot {slot} already holds a {existing.Algorithm} key. Refusing to destroy it.");
        }

        // The PIN policy is decided here, by what the token can do, and it
        // cannot be changed later without replacing the key. A Bio gets
        // MatchOnce so a fingerprint satisfies the slot; anything else gets
        // Once, which means a PIN.
        //
        // Found the hard way: a key generated with Once on a Bio refused to
        // sign with 6982 immediately after VERIFY 96 answered 9000. The user
        // had been verified and the key still would not have it.
        var biometric = session.GetBiometricMetadata() is { FingerprintsEnrolled: true };

        var policy = biometric ? PinPolicy.MatchOnce : PinPolicy.Once;

        // Never is a legal PIV value and it is never what Blinky wants: a key
        // that signs without asking anybody anything is a key that signs for
        // whoever has the token in their hand, which is the property the whole
        // system exists to avoid. Asserted here rather than trusted from
        // above, because this is the last place that can still refuse.
        if (policy is PinPolicy.Never or PinPolicy.Unknown)
        {
            throw new InvalidOperationException(
                $"Refusing to generate a key in {slot} that needs no verification.");
        }

        var generated = session.GenerateKeyPair(slot, algorithm,
            policy, TouchPolicy.Never);

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

        await VerifyUserAsync(session, serial, job, backend, attempt, ct);

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

        // What the card ended up with, not what was asked for. A slot that came
        // back needing no verification is worth failing over even though the
        // certificate is already on it - the alternative is a credential nobody
        // has to prove anything to use, recorded as a success.
        if (session.GetSlotMetadata(slot) is { } written
            && written.PinPolicy is PinPolicy.Never)
        {
            throw new InvalidOperationException(
                $"Slot {slot} reports PIN policy {written.PinPolicy} after generation. "
                + "The key would sign for anybody holding the token.");
        }

        if (readBack.Thumbprint != certificate.Thumbprint)
        {
            throw new InvalidOperationException(
                $"Slot {slot} holds a different certificate than the one written.");
        }

        await backend.ConfirmInstalledAsync(
            new CredentialInstalled(issued.CredentialId, readBack.Thumbprint), ct);

        logger.LogInformation("Token {Serial} slot {Slot} now holds {Subject}, issued by {Issuer}",
            serial, slot, readBack.Subject, issued.IssuerSubject);

        // Said out loud when it happened. The recovery is silent by design, and
        // a workstation where something resets the card mid-operation is worth
        // knowing about even when every job still succeeds - it is the
        // difference between "this machine is slow" and "this machine has a
        // second program fighting us for the reader".
        if (session.Connection.CardResets is > 0 and var resets)
        {
            logger.LogWarning(
                "The card was reset {Count} time(s) during this job and recovered from. "
                + "Something else on this machine is taking the reader - the certificate "
                + "propagation service and card minidrivers both do.", resets);
        }
    }

    /// <summary>
    /// Has the person prove they are there — by fingerprint where the card can,
    /// by PIN where it cannot.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The card decides, not the model name and not a setting. A Bio
    /// Multi-protocol answers slot 96 with an attempt count; everything else
    /// answers <c>6A88</c>, and that is the whole detection.
    /// </para>
    /// <para>
    /// A failed match falls back to the PIN rather than failing the job. Three
    /// attempts is not many, a cold or wet finger is not a security event, and
    /// on a Bio the PIN is the only way in once biometrics block — the product
    /// line ships with no PUK.
    /// </para>
    /// </remarks>
    private async Task VerifyUserAsync(PivSession session, long serial, JobEnvelope job,
        BackendClient backend, int attempt, CancellationToken ct)
    {
        var biometrics = session.GetBiometricMetadata();

        if (biometrics is { FingerprintsEnrolled: true, AttemptsRemaining: > 0 })
        {
            await Report(backend, job, attempt, "VerifyUser", ct,
                JobState.AwaitingUser, "waiting for a fingerprint");

            // Told first, because the sensor lights the moment the APDU goes
            // out and the call then blocks. A lit sensor with nothing on screen
            // is a program that looks frozen.
            await prompts.ShowFingerprintAsync(serial, biometrics.AttemptsRemaining,
                "Blinky is issuing a certificate onto your key.", ct);

            try
            {
                session.VerifyBiometric();

                await prompts.DismissAsync(ct);

                logger.LogInformation("Token {Serial}: the user was verified by fingerprint",
                    serial);

                return;
            }
            catch (PivException ex)
            {
                await prompts.DismissAsync(ct);

                logger.LogWarning("Token {Serial}: the fingerprint did not match ({Message}); "
                                  + "asking for the PIN instead", serial, ex.Message);
            }
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

    /// <summary>
    /// The key the card should generate, from the job, or the default.
    /// </summary>
    /// <remarks>
    /// RSA 2048 by default, and not because it is the better cryptography - it
    /// is not. It is the one a Windows workstation accepts without being
    /// configured first.
    ///
    /// The inbox smart-card credential provider does not enumerate ECC
    /// certificates unless EnumerateECCCerts is set under
    /// HKLM\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider.
    /// Without it an ECC credential that is present, valid and correctly
    /// chained produces "no valid certificates were found on this smart card"
    /// at the logon screen, while certutil -scinfo reports a missing keyset
    /// for a key the card itself will happily describe. Neither message
    /// mentions a policy setting, and the card is the first thing anybody
    /// suspects.
    ///
    /// So a deployment that wants ECC asks for it and turns the setting on. A
    /// deployment that has not thought about it gets the one that works.
    /// </remarks>
    internal static PivAlgorithm ParseAlgorithm(string? requested)
    {
        if (string.IsNullOrWhiteSpace(requested))
        {
            return PivAlgorithm.Rsa2048;
        }

        return Enum.TryParse<PivAlgorithm>(requested, ignoreCase: true, out var parsed)
            ? parsed
            : throw new InvalidOperationException(
                $"'{requested}' is not a key algorithm this agent knows.");
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
