using System.Runtime.Versioning;
using Blinky.Contracts;
using Blinky.Piv;
using Blinky.Piv.Pcsc;

namespace Blinky.Agent.Service;

/// <summary>
/// What the person at the keyboard may do to a token in front of them.
/// </summary>
/// <remarks>
/// <para>
/// Every APDU lives here, in the service, and none in the window. The UI holds
/// no reader handle and no card state of its own: it renders what this returns
/// and forgets it. A tray application that cached what it last saw would be a
/// second source of truth that goes stale exactly when the token leaves the
/// machine.
/// </para>
/// <para>
/// The policy is applied here too, not only where somebody types. A rule
/// checked in the window is a rule the next window does not have.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class CardOperations(
    InventoryCollector collector,
    CardGate gate,
    ILogger<CardOperations> logger)
{
    /// <summary>
    /// Everything on the readers of this machine, read now.
    /// </summary>
    public IReadOnlyList<TokenView> ListTokens()
    {
        using var held = gate.Acquire();

        var sweep = collector.ReadAll();

        return [.. sweep.Tokens.Select(View)];
    }

    private static TokenView View(TokenInventoryReport token) => new(
        token.Serial,
        token.ReaderName,
        token.FirmwareVersion,
        token.Pin.RemainingRetries,

        // Total retries of zero means the credential does not exist, which is
        // how a Bio says it has no PUK. That is not the same as a PUK with no
        // attempts left, which is a token nobody can rescue.
        token.Puk.TotalRetries is > 0,

        [.. token.Slots.Select(View)]);

    private static SlotView View(SlotReport slot) => new(
        slot.SlotId,
        slot.CertificateSubject,
        slot.CertificateIssuer,
        slot.NotAfter,
        slot.KeyAlgorithm,

        // A key with no certificate is the residue of an enrolment that failed
        // after generating. Not a fault, and not nothing: it is why a retry
        // into this slot will be refused.
        slot.HasKey && !slot.HasCertificate);

    /// <summary>
    /// Changes a PIN. The values reach the card and nowhere else.
    /// </summary>
    public AgentResponse ChangePin(long serial, string? currentPin, string? newPin,
        PinComplexityPolicy policy)
    {
        var verdict = PinRules.Check(newPin, policy, serial);
        if (!verdict.IsAcceptable)
        {
            // Refused before a single byte reaches the card, so no attempt is
            // spent on a PIN the policy was never going to allow.
            return AgentResponse.Failed(verdict.Explanation);
        }

        if (string.IsNullOrEmpty(currentPin))
        {
            return AgentResponse.Failed("The current PIN is required.");
        }

        return OnToken(serial, session =>
        {
            session.ChangePin(currentPin, newPin!);

            logger.LogInformation("The PIN on token {Serial} was changed", serial);

            return new AgentResponse(true);
        });
    }

    /// <summary>
    /// Sets a new PIN using the PUK, which is the only way back from a blocked
    /// one.
    /// </summary>
    public AgentResponse UnblockPin(long serial, string? puk, string? newPin, PinComplexityPolicy policy)
    {
        var verdict = PinRules.Check(newPin, policy, serial, puk);
        if (!verdict.IsAcceptable)
        {
            return AgentResponse.Failed(verdict.Explanation);
        }

        if (string.IsNullOrEmpty(puk))
        {
            return AgentResponse.Failed("The PUK is required.");
        }

        return OnToken(serial, session =>
        {
            session.UnblockPin(puk, newPin!);

            logger.LogInformation("The PIN on token {Serial} was unblocked", serial);

            return new AgentResponse(true);
        });
    }

    /// <summary>
    /// Finds the token by serial and runs one operation inside a single
    /// transaction, translating whatever the card said into something a person
    /// can act on.
    /// </summary>
    private AgentResponse OnToken(long serial, Func<PivSession, AgentResponse> operation)
    {
        try
        {
            using var held = gate.Acquire();
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

                using var transaction = connection.BeginTransaction();

                if (!session.Select() || session.GetSerialNumber() != (uint)serial)
                {
                    continue;
                }

                return operation(session);
            }

            return AgentResponse.Failed($"Token {serial} is not in any reader on this machine.");
        }
        catch (PivVerificationFailedException ex)
        {
            // The card rejected the value. The count is the difference between
            // "try again" and "one more and this token is blocked", and it is
            // the only number worth putting in front of somebody here.
            return AgentResponse.Failed(ex.Message, ex.RetriesLeft);
        }
        catch (PivException ex)
        {
            return AgentResponse.Failed(ex.Message);
        }
        catch (PcscException ex)
        {
            return AgentResponse.Failed(ex.Message);
        }
    }
}
