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
    BackendClient backend,
    ILogger<CardOperations> logger)
{
    /// <summary>
    /// Everything on the readers of this machine, read now, and whether Blinky
    /// put it there.
    /// </summary>
    /// <remarks>
    /// The card is read first and the backend asked afterwards, in that order
    /// and never merged into one step: the card is the fact, and what the
    /// backend holds is a claim about it. Where the backend cannot be reached
    /// the list is still correct and every slot reads <see cref="SlotManagement.Unknown"/>.
    /// </remarks>
    public async Task<IReadOnlyList<TokenView>> ListTokensAsync(CancellationToken ct)
    {
        InventorySweep sweep;

        using (gate.Acquire())
        {
            sweep = collector.ReadAll();
        }

        var views = new List<TokenView>(sweep.Tokens.Count);

        foreach (var token in sweep.Tokens)
        {
            var known = await backend.GetKnownCredentialsAsync(token.Serial, ct);

            if (known is null)
            {
                logger.LogDebug("The backend could not be asked about token {Serial}; "
                                + "its slots are reported as unknown", token.Serial);
            }

            views.Add(View(token, known));
        }

        return views;
    }

    private static TokenView View(TokenInventoryReport token,
        IReadOnlyList<KnownCredential>? known) => new(
        token.Serial,
        token.ReaderName,
        token.FirmwareVersion,
        token.Pin.RemainingRetries,

        // Total retries of zero means the credential does not exist, which is
        // how a Bio says it has no PUK. That is not the same as a PUK with no
        // attempts left, which is a token nobody can rescue.
        token.Puk.TotalRetries is > 0,

        [.. token.Slots.Select(slot => View(slot, known))],

        // IsDefault is null on firmware too old to be asked. Unknown is not the
        // same as fine, but warning about a token that never said so would be
        // worse: it teaches people to dismiss the banner.
        token.Pin.IsDefault ?? false,
        token.Puk.IsDefault ?? false,
        token.Puk.RemainingRetries,
        token.ManagementKey?.IsDefault ?? false,
        token.ManagementKey?.Algorithm,
        token.FormFactor,
        token.IsFipsDevice,
        token.Biometrics?.FingerprintsEnrolled ?? false,

        // Null metadata means the card refused slot 96, which is how a
        // non-biometric token answers - never inferred from the model name.
        token.Biometrics switch
        {
            null => BiometricAvailability.NotSupported,
            { AttemptsRemaining: 0 } => BiometricAvailability.Blocked,
            { FingerprintsEnrolled: false } => BiometricAvailability.NotEnrolled,
            _ => BiometricAvailability.Enrolled,
        },
        token.Biometrics?.AttemptsRemaining);

    private static SlotView View(SlotReport slot, IReadOnlyList<KnownCredential>? known) => new(
        slot.SlotId,
        slot.CertificateSubject,
        slot.CertificateIssuer,
        slot.NotAfter,
        slot.KeyAlgorithm,

        // A key with no certificate is the residue of an enrolment that failed
        // after generating. Not a fault, and not nothing: it is why a retry
        // into this slot will be refused.
        slot.HasKey && !slot.HasCertificate,

        Manages(slot, known),
        slot.PinPolicy,
        slot.TouchPolicy,
        slot.PublicKeySha256);

    /// <summary>
    /// Compares the key on the card with the key the backend recorded issuing.
    /// </summary>
    /// <remarks>
    /// The public key rather than the certificate, because a certificate can be
    /// swapped into a slot while the key stays where it was — and the key is
    /// the thing the card proved it holds.
    /// </remarks>
    private static SlotManagement Manages(SlotReport slot, IReadOnlyList<KnownCredential>? known)
    {
        if (!slot.HasCertificate)
        {
            // A bare key is not a credential yet, and calling it unmanaged
            // would point at the wrong problem.
            return slot.HasKey ? SlotManagement.Unknown : SlotManagement.Empty;
        }

        if (known is null || slot.PublicKeySha256 is not { } onCard)
        {
            return SlotManagement.Unknown;
        }

        var matches = known.Any(credential =>
            string.Equals(credential.SlotId, slot.SlotId, StringComparison.OrdinalIgnoreCase)
            && string.Equals(credential.PublicKeySha256, onCard, StringComparison.OrdinalIgnoreCase));

        return matches ? SlotManagement.Managed : SlotManagement.Unmanaged;
    }

    /// <summary>
    /// Reads one slot's certificate.
    /// </summary>
    /// <remarks>
    /// No verification asked for, and none needed: a certificate is the public
    /// half, readable by anything that can talk to the card. The private key it
    /// belongs to is what needs a PIN or a fingerprint, and nothing here goes
    /// near that.
    /// </remarks>
    public AgentResponse ReadCertificate(long serial, string? slotId)
    {
        if (Slot(slotId) is not { } slot)
        {
            return AgentResponse.Failed($"{slotId} is not a credential slot.");
        }

        return OnToken(serial, session =>
        {
            var certificate = session.GetCertificateAsX509(slot);

            return certificate is null
                ? AgentResponse.Failed($"Slot {slot} holds no certificate.")
                : new AgentResponse(true, CertificatePem: certificate.ExportCertificatePem());
        });
    }

    /// <summary>
    /// Removes a certificate from a slot.
    /// </summary>
    /// <remarks>
    /// The key stays. That is what the card does and it is worth saying out
    /// loud: the slot afterwards reads as holding a key with no certificate,
    /// which is the same shape as an enrolment that died halfway - and it is
    /// why a fresh enrolment into that slot is refused rather than quietly
    /// destroying what is there.
    /// </remarks>
    public async Task<AgentResponse> DeleteCertificateAsync(long serial, string? slotId,
        bool alsoTheKey, CancellationToken ct)
    {
        if (Slot(slotId) is not { } slot)
        {
            return AgentResponse.Failed($"{slotId} is not a credential slot.");
        }

        // Asked before anything is touched, because the answer decides whether
        // this is allowed at all.
        var known = await backend.GetKnownCredentialsAsync(serial, ct);

        var management = known is null
            ? SlotManagement.Unknown
            : known.Any(c => string.Equals(c.SlotId, slot.Name, StringComparison.OrdinalIgnoreCase))
                ? SlotManagement.Managed
                : SlotManagement.Unmanaged;

        if (management == SlotManagement.Managed)
        {
            // Blinky issued this. Taking it off the card from a tray leaves the
            // backend holding a credential it believes is installed - the exact
            // divergence that Issued and Installed exist to make visible,
            // created deliberately by the tool meant to prevent it. Removing a
            // credential Blinky issued is a revocation, and revocation is the
            // server's decision.
            return AgentResponse.Failed(
                $"Slot {slot} holds a credential Blinky issued. Revoke it from the console "
                + "instead - deleting it here would leave the backend believing it is still "
                + "on the token.");
        }

        if (management == SlotManagement.Unknown)
        {
            // Not unmanaged. The backend could not be asked, so there is no way
            // to tell whether this is somebody else's certificate or one of
            // ours, and the destructive reading of a shrug is the wrong one.
            return AgentResponse.Failed(
                "The backend cannot be reached, so there is no way to tell whether this "
                + "credential is one Blinky issued. Nothing was deleted.");
        }

        return OnToken(serial, session =>
        {
            var key = session.GetManagementKeyMetadata()
                ?? throw new InvalidOperationException(
                    "This firmware will not say which management key algorithm it holds.");

            session.AuthenticateManagementKey(ManagementKey.Default(key.Algorithm));
            session.DeleteCertificate(slot);

            logger.LogWarning("The certificate in slot {Slot} of token {Serial} was deleted "
                              + "(it was not one Blinky issued)", slot, serial);

            if (alsoTheKey)
            {
                // Firmware 5.7 and later. Older tokens throw, and the message
                // says why rather than leaving somebody to wonder whether the
                // slot is empty: on a 5.4 a key can only be overwritten.
                session.DeleteKey(slot);

                logger.LogWarning("The key in slot {Slot} of token {Serial} was destroyed",
                    slot, serial);
            }

            return new AgentResponse(true);
        });
    }

    private static PivSlot? Slot(string? slotId)
    {
        var slot = PivSlot.Credentials.FirstOrDefault(s =>
            s.Name.Equals(slotId, StringComparison.OrdinalIgnoreCase));

        return slot.Id == 0 ? null : slot;
    }

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

                PivConnection connection;
                PivSession session;
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
                catch (Exception ex) when (ex is PcscException or PivException
                                              or PivProtocolException)
                {
                    // A reader that will not answer is skipped, not fatal. One
                    // unresponsive reader took down an enrolment aimed at a
                    // token two readers along before this was here.
                    logger.LogWarning("Reader {Reader} could not be used: {Message}",
                        reader, ex.Message);

                    continue;
                }

                using (connection)
                using (transaction)
                {
                    return operation(session);
                }
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
