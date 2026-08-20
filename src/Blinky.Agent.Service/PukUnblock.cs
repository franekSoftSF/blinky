using System.Runtime.Versioning;
using Blinky.Contracts;
using Blinky.Piv;
using Blinky.Piv.Pcsc;

namespace Blinky.Agent.Service;

/// <summary>
/// Unblocks a PIN without anybody knowing a PUK.
/// </summary>
/// <remarks>
/// <para>
/// The wrapper that makes a static PUK stop being one. PIV offers a single
/// unblock command, <c>RESET RETRY COUNTER</c>, and it takes a PUK in its data
/// field — there is no challenge-response unblock to reach for, on a YubiKey or
/// on any other PIV card. What can be built on top of it is this: the value is
/// never chosen by a person, never typed, never shown, and never survives the
/// operation.
/// </para>
/// <para>
/// Four steps that must not come apart:
/// </para>
/// <list type="number">
/// <item>Ask the backend for the PUK the card holds and the one to replace it.</item>
/// <item><c>RESET RETRY COUNTER</c> — the PIN is unblocked and set.</item>
/// <item><c>CHANGE REFERENCE DATA</c> on the PUK slot — the disclosed value is spent.</item>
/// <item>Tell the backend the card took it, so escrow promotes the replacement.</item>
/// </list>
/// <para>
/// Steps two and three share one PC/SC transaction. Between them the card holds
/// a PUK that has been out of escrow, which is the whole window this design
/// exists to keep short.
/// </para>
/// <para>
/// If step three fails the card keeps the old PUK and the backend keeps both,
/// so the next attempt still works. If step four fails the same is true. The
/// arrangement is deliberately biased towards leaving a usable token behind.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class PukUnblock(
    BackendClient backend,
    CardGate gate,
    ILogger<PukUnblock> logger)
{
    public async Task<AgentResponse> UnblockAsync(long serial, string newPin,
        PinComplexityPolicy policy, CancellationToken ct)
    {
        var verdict = PinRules.Check(newPin, policy, serial);
        if (!verdict.IsAcceptable)
        {
            // Refused before the backend is asked, so a PIN the policy was
            // never going to allow does not cause a PUK to be disclosed.
            return AgentResponse.Failed(verdict.Explanation);
        }

        var material = await backend.CheckoutPukAsync(serial, ct);

        if (material is null)
        {
            return AgentResponse.Failed(
                "The backend would not release this token's PUK. It may have no PUK, or one "
                + "Blinky never set.");
        }

        using var held = await gate.AcquireAsync(ct);

        var rotated = OnCard(serial, material, newPin);

        if (!rotated.Succeeded)
        {
            return rotated;
        }

        // Told last, and only about a card that took the change. Promoting the
        // replacement before the card has it would leave escrow holding a value
        // the token never saw.
        if (!await backend.ConfirmPukRotatedAsync(serial, material.CheckoutId, ct))
        {
            logger.LogError("Token {Serial} took a new PUK but the backend did not record it. "
                            + "Escrow still holds both.", serial);
        }

        return new AgentResponse(true);
    }

    private AgentResponse OnCard(long serial, PukMaterial material, string newPin)
    {
        try
        {
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

                session.UnblockPin(material.CurrentPuk, newPin);

                // Spent the moment it is used. A PUK that stayed on the card
                // after leaving escrow is exactly the static secret this whole
                // arrangement replaces.
                session.ChangePuk(material.CurrentPuk, material.NextPuk);

                logger.LogInformation("Token {Serial} was unblocked and its PUK rotated", serial);

                return new AgentResponse(true);
            }

            return AgentResponse.Failed($"Token {serial} is not in any reader on this machine.");
        }
        catch (PivVerificationFailedException ex)
        {
            // The escrowed PUK was not the one on the card. Somebody else has
            // been here, and the count says how many attempts remain before
            // the token becomes unrecoverable.
            logger.LogWarning("Token {Serial} refused the escrowed PUK: {Message}",
                serial, ex.Message);

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
