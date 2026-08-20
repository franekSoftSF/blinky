using System.Globalization;
using System.Security.Cryptography;
using Blinky.Contracts;
using Blinky.Piv;
using Blinky.Piv.Attestation;
using Blinky.Piv.Pcsc;

namespace Blinky.Agent.Service;

/// <summary>
/// Turns one read-only pass over a token into a report for the backend.
/// </summary>
/// <remarks>
/// Reports facts and no conclusions - see <see cref="TokenInventoryReport"/>.
/// Nothing here writes to a card.
/// </remarks>
public sealed class InventoryCollector(ILogger<InventoryCollector> logger)
{
    private readonly AttestationVerifier verifier = new(YubicoRoots.PivAttestation);

    /// <summary>
    /// Reads every reader that holds a card with a PIV applet. Readers with no
    /// card, and cards that are something else, are skipped rather than logged
    /// as failures: on a machine with Windows Hello that is the normal state of
    /// most of the list.
    /// </summary>
    public InventorySweep ReadAll()
    {
        if (!PcscContext.IsSupported)
        {
            return new InventorySweep([], []);
        }

        using var context = PcscContext.Establish();
        var tokens = new List<TokenInventoryReport>();
        var unsupported = new List<UnsupportedCardReport>();

        foreach (var reader in context.ListReaders())
        {
            try
            {
                Read(context, reader, tokens, unsupported);
            }
            catch (Exception ex) when (ex is PcscException or PivException or PivProtocolException)
            {
                logger.LogWarning("Reader {Reader}: {Message}", reader, ex.Message);
            }
        }

        return new InventorySweep(tokens, unsupported);
    }

    private void Read(PcscContext context, string reader,
        List<TokenInventoryReport> tokens, List<UnsupportedCardReport> unsupported)
    {
        using var card = context.Connect(reader);
        if (card is null)
        {
            return;
        }

        using var connection = new PivConnection(card, ownsTransport: false);
        var session = new PivSession(connection);

        using var transaction = connection.BeginTransaction();

        // No PIV applet at all - a virtual reader, or a card that is something
        // else entirely. Normal, and not worth a word.
        if (!session.Select())
        {
            return;
        }

        var token = session.ReadInventory();

        if (token.SerialNumber is not { } serial)
        {
            // Speaks PIV, but answers none of the Yubico instructions. Blinky
            // cannot manage it and must say so rather than leave the reader
            // looking empty.
            unsupported.Add(new UnsupportedCardReport(reader,
                "a PIV card that does not answer the Yubico instructions - "
                + "outside what this version manages",
                token.Pin.RemainingRetries));

            return;
        }

        var attestation = ReadAttestation(session, serial);
        var slots = token.Slots.Select(slot => Describe(slot)).ToList();

        tokens.Add(new TokenInventoryReport(
            Protocol.SchemaVersion,
            serial,
            reader,
            token.Firmware == FirmwareVersion.Unknown ? null : token.Firmware.ToString(),
            attestation?.Attestation?.FormFactor.ToString(),
            attestation?.Attestation?.IsFipsDevice ?? false,
            AttestationThumbprint(session),
            attestation?.IsTrusted ?? false,
            Describe(token.Pin),
            Describe(token.Puk),
            token.Biometrics is null
                ? null
                : new BiometricReport(token.Biometrics.FingerprintsEnrolled,
                    token.Biometrics.AttemptsRemaining, token.Biometrics.TemporaryPinSet),
            token.ManagementKey is null
                ? null
                : new ManagementKeyReport(token.ManagementKey.Algorithm.ToString(),
                    token.ManagementKey.IsDefault, token.ManagementKey.TouchPolicy.ToString()),
            slots));
    }

    /// <summary>
    /// Attests slot 9A when it holds a key, and verifies the chain. This is
    /// where the form factor comes from - it is in the attestation and nowhere
    /// else, so a blank token simply has none.
    /// </summary>
    private AttestationResult? ReadAttestation(PivSession session, uint serial)
    {
        var leaf = session.Attest(PivSlot.Authentication);
        if (leaf is null)
        {
            return null;
        }

        var intermediate = session.GetAttestationCertificate();
        if (intermediate is null)
        {
            return null;
        }

        var result = verifier.Verify(leaf, intermediate, PivSlot.Authentication, serial);

        if (!result.IsTrusted)
        {
            logger.LogWarning("Token {Serial}: attestation {Result}", serial, result);
        }

        return result;
    }

    private static string? AttestationThumbprint(PivSession session)
    {
        try
        {
            return session.GetAttestationCertificate()?.Thumbprint;
        }
        catch (PivException)
        {
            return null;
        }
    }

    private static CredentialReport Describe(PinMetadata credential) => new(
        credential.State switch
        {
            PinState.Default => true,
            PinState.Unknown => null,
            _ => false,
        },
        credential.State is PinState.Blocked,
        credential.RemainingRetries,
        credential.TotalRetries);

    private static SlotReport Describe(SlotInventory slot)
    {
        string? publicKey = null;
        string? subject = null;
        string? thumbprint = null;
        DateTimeOffset? notBefore = null;
        DateTimeOffset? notAfter = null;

        if (slot.CertificateDer is { } der)
        {
            using var certificate =
                System.Security.Cryptography.X509Certificates.X509CertificateLoader
                    .LoadCertificate(der);

            subject = certificate.Subject;
            thumbprint = certificate.Thumbprint;
            notBefore = certificate.NotBefore;
            notAfter = certificate.NotAfter;

            // Hash of the SubjectPublicKeyInfo: the join between what a CA
            // signed and what the card proved it holds, and how a certificate
            // swapped in from outside is spotted.
            publicKey = Convert.ToHexString(SHA256.HashData(
                certificate.PublicKey.ExportSubjectPublicKeyInfo()));
        }

        return new SlotReport(
            slot.Slot.Name,
            slot.Metadata is not null,
            slot.HasCertificate,
            slot.Metadata?.Algorithm.ToString(),
            slot.Metadata?.PinPolicy.ToString(),
            slot.Metadata?.TouchPolicy.ToString(),
            publicKey,
            subject,
            thumbprint,
            notBefore,
            notAfter);
    }
}

/// <summary>
/// One pass over the readers: what can be managed, and what was found but
/// cannot be.
/// </summary>
public sealed record InventorySweep(
    IReadOnlyList<TokenInventoryReport> Tokens,
    IReadOnlyList<UnsupportedCardReport> Unsupported);
