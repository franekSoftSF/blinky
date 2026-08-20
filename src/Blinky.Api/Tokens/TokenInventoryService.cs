using Blinky.Api.Persistence;
using Blinky.Contracts;
using Blinky.Domain;
using Blinky.Domain.Entities;
using NHibernate.Linq;

namespace Blinky.Api.Tokens;

/// <summary>
/// Takes an agent's report of a token and decides what it means.
/// </summary>
/// <remarks>
/// The agent reports facts; every judgement is made here. That is the same rule
/// as everywhere else in the system - no authorisation or policy decision is
/// taken on a workstation - and it is what lets one rule change apply to a
/// fleet without shipping a new agent.
/// </remarks>
public sealed class TokenInventoryService(Database database, ILogger<TokenInventoryService> logger)
{
    public InventoryAccepted Accept(TokenInventoryReport report)
    {
        using var session = database.OpenSession();
        using var transaction = session.BeginTransaction();

        var now = DateTime.UtcNow;
        var token = session.Query<Token>().SingleOrDefault(t => t.Serial == report.Serial);
        var isNew = token is null;

        token ??= new Token
        {
            Serial = report.Serial,
            State = TokenState.Detected,
            CreatedAt = now,
        };

        token.FirmwareVersion = report.FirmwareVersion ?? token.FirmwareVersion;
        token.FormFactor = report.FormFactor ?? token.FormFactor;
        token.AttestationThumbprint = report.AttestationThumbprint ?? token.AttestationThumbprint;
        token.PinState = TokenClassification.Pin(report.Pin);
        token.PukState = TokenClassification.Puk(report.Puk, report.Biometrics);
        token.BiometricState = TokenClassification.Biometrics(report.Biometrics);
        token.PinRetriesLeft = (short?)report.Pin.RemainingRetries;
        token.PukRetriesLeft = (short?)report.Puk.RemainingRetries;
        token.BiometricAttemptsLeft = (short?)report.Biometrics?.AttemptsRemaining;
        token.ManagementKeyAlgorithm = report.ManagementKey?.Algorithm;
        token.ManagementKeyState =
            TokenClassification.ManagementKey(report.ManagementKey, token.ManagementKeyVersion);
        token.LastSeenAt = now;
        token.UpdatedAt = now;

        // A token whose attestation chains to the pinned Yubico root has proved
        // it is genuine hardware; that is what Registered means. Everything
        // else stays Detected until it can prove it.
        if (token.State is TokenState.Detected && report.AttestationVerified)
        {
            token.State = TokenState.Registered;
        }

        session.SaveOrUpdate(token);

        UpdateSlots(session, token, report, now);

        if (isNew)
        {
            session.Save(new AuditEvent
            {
                OccurredAt = now,
                EventType = "token.detected",
                Actor = report.ReaderName,
                SubjectType = nameof(Token),
                SubjectId = token.Id,
                TokenSerial = token.Serial,
                Detail = $$"""{"firmware":"{{report.FirmwareVersion}}","verified":{{
                    (report.AttestationVerified ? "true" : "false")}}}""",
            });

            logger.LogInformation("Token {Serial} seen for the first time, firmware {Firmware}",
                report.Serial, report.FirmwareVersion);
        }

        transaction.Commit();

        return new InventoryAccepted(token.Id, token.State.ToString(), token.PukState.ToString(),
            token.IsUnrecoverable, isNew);
    }

    private static void UpdateSlots(NHibernate.ISession session, Token token,
        TokenInventoryReport report, DateTime now)
    {
        var existing = session.Query<Slot>()
            .Where(s => s.Token.Id == token.Id)
            .ToDictionary(s => s.SlotId, StringComparer.OrdinalIgnoreCase);

        foreach (var reported in report.Slots)
        {
            if (!existing.TryGetValue(reported.SlotId, out var slot))
            {
                slot = new Slot { Token = token, SlotId = reported.SlotId };
            }

            slot.KeyAlgorithm = reported.KeyAlgorithm;
            slot.PinPolicy = reported.PinPolicy;
            slot.TouchPolicy = reported.TouchPolicy;
            slot.PublicKeySha256 = reported.PublicKeySha256 is null
                ? null
                : Convert.FromHexString(reported.PublicKeySha256);
            slot.State = ClassifySlot(session, token, reported);
            slot.UpdatedAt = now;

            session.SaveOrUpdate(slot);
        }
    }

    /// <summary>
    /// A certificate Blinky did not issue is <see cref="SlotState.Stale"/>, not
    /// provisioned. This is what every token ever touched by <c>ykman</c> looks
    /// like, and treating it as ours - or silently overwriting it - is the
    /// wrong default. See docs/02-data-model.md.
    /// </summary>
    private static SlotState ClassifySlot(NHibernate.ISession session, Token token,
        SlotReport reported)
    {
        if (!reported.HasKey && !reported.HasCertificate)
        {
            return SlotState.Empty;
        }

        if (!reported.HasCertificate)
        {
            return SlotState.KeyPresent;
        }

        var ours = session.Query<Credential>().Any(c =>
            c.Token.Id == token.Id
            && c.SlotId == reported.SlotId
            && c.State != Domain.CredentialState.Revoked);

        return ours ? SlotState.Provisioned : SlotState.Stale;
    }

}
