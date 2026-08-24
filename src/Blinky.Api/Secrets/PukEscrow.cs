using System.Security.Cryptography;
using System.Text;
using Blinky.Api.Persistence;
using Blinky.Contracts;
using Blinky.Domain;
using Blinky.Domain.Entities;
using NHibernate.Linq;

namespace Blinky.Api.Secrets;

/// <summary>
/// Holds the PUK so that nobody has to.
/// </summary>
/// <remarks>
/// <para>
/// A PUK a person knows is a PUK that is written down, shared, and the same on
/// every token in a drawer. The way out is not to let people choose a better
/// one — it is to make the value something no person ever sees: random per
/// token, encrypted at rest, released to a workstation for the seconds an
/// unblock takes, and replaced immediately afterwards.
/// </para>
/// <para>
/// What that gives is challenge and response in the sense that matters here:
/// the card presents an identity, the server decides and returns the value that
/// answers it, and the value is spent on use. It is <b>not</b> a
/// challenge-response exchange with the card, and it cannot be — PIV has one
/// unblock command, <c>RESET RETRY COUNTER</c>, and it takes a PUK in its data
/// field. There is no APDU to build the other thing on. See docs/10-agent-ui.md.
/// </para>
/// <para>
/// The KEK protecting these is one of the three secrets in docs/06-security.md
/// whose loss means every escrowed PUK.
/// </para>
/// </remarks>
public sealed class PukEscrow(Database database, byte[] kek, ILogger<PukEscrow> logger)
{
    /// <summary>
    /// Eight digits, which is the PIV maximum and what every token ships with.
    /// </summary>
    private const int PukLength = 8;

    /// <summary>The value PIV tokens leave the factory with.</summary>
    public const string FactoryPuk = "12345678";

    /// <summary>
    /// Hands out the PUK currently on the card and the one that will replace
    /// it.
    /// </summary>
    /// <remarks>
    /// Both at once, in one call, because the agent needs the second before it
    /// can spend the first: unblock with the current value, then change the PUK
    /// to the next one, inside the same transaction with the card. Two round
    /// trips would put a network between two APDUs that must not be separated.
    /// </remarks>
    /// <param name="reason">
    /// Why the PUK is being taken out, for the audit row. Not decoration: that
    /// row is named in docs/06 as an alerting trigger, and "somebody unblocked
    /// a PIN" and "a card was personalised" deserve different attention.
    /// It was hard-coded to "unblock", which made a personalisation
    /// indistinguishable from a desk-side rescue when reading the trail back.
    /// </param>
    public PukCheckout? Checkout(long serial, string actor, string reason = "unblock")
    {
        using var session = database.OpenSession();
        using var transaction = session.BeginTransaction();

        var token = session.Query<Token>().SingleOrDefault(t => t.Serial == serial);
        if (token is null)
        {
            return null;
        }

        if (token.PukState is CredentialSecretState.NotApplicable
            or CredentialSecretState.Disabled)
        {
            // A Bio has no PUK at all and a disabled one cannot be used. Both
            // are refusals rather than failures, and the caller must be able to
            // say which.
            throw new PukUnavailableException(
                $"Token {serial} has no usable PUK ({token.PukState}).");
        }

        var current = Current(session, token);

        var next = Generate();
        var pending = Wrap(token, next, SecretKind.PukPending);

        session.Save(pending);

        session.Save(new AuditEvent
        {
            OccurredAt = DateTime.UtcNow,
            EventType = "puk.disclosed",
            Actor = actor,
            SubjectType = nameof(Token),
            SubjectId = token.Id,
            TokenSerial = serial,

            // The disclosure is the event, never the value. This row is exempt
            // from retention precisely because it is the record that somebody
            // took a PUK out of escrow.
            Detail = $$"""{"reason":"{{reason}}","pending":"{{pending.Id}}"}""",
        });

        transaction.Commit();

        logger.LogWarning("The PUK for token {Serial} was disclosed to {Actor}", serial, actor);

        return new PukCheckout(pending.Id, current, next);
    }

    /// <summary>
    /// Promotes the replacement once the card has taken it.
    /// </summary>
    /// <remarks>
    /// Only on the agent's word that the card accepted the change. Until then
    /// both values exist here and the previous one stays usable, because an
    /// unblock that died between the two APDUs leaves the card holding the old
    /// PUK and nothing else knows which.
    /// </remarks>
    public bool Commit(long serial, Guid checkoutId)
    {
        using var session = database.OpenSession();
        using var transaction = session.BeginTransaction();

        var token = session.Query<Token>().SingleOrDefault(t => t.Serial == serial);
        if (token is null)
        {
            return false;
        }

        var pending = session.Get<SecretEnvelope>(checkoutId);
        if (pending is null || pending.Token.Id != token.Id
            || pending.Kind != SecretKind.PukPending)
        {
            return false;
        }

        foreach (var superseded in session.Query<SecretEnvelope>()
                     .Where(e => e.Token.Id == token.Id && e.Kind == SecretKind.Puk)
                     .ToList())
        {
            session.Delete(superseded);
        }

        pending.Kind = SecretKind.Puk;
        session.Update(pending);

        // Set, not Default: whatever the card shipped with, it is now holding
        // a value only this escrow knows.
        token.PukState = CredentialSecretState.Set;
        token.UpdatedAt = DateTime.UtcNow;
        session.Update(token);

        session.Save(new AuditEvent
        {
            OccurredAt = DateTime.UtcNow,
            EventType = "puk.rotated",
            SubjectType = nameof(Token),
            SubjectId = token.Id,
            TokenSerial = serial,
            Detail = $$"""{"checkout":"{{checkoutId}}"}""",
        });

        transaction.Commit();

        return true;
    }

    /// <summary>
    /// Answers a challenge read down a telephone from a machine with no
    /// network.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The response is the PUK the card holds, and the replacement is derived
    /// from it and the challenge — so the workstation arrives at the same new
    /// value without being told, and the code that was spoken aloud is dead as
    /// soon as the card takes it. See <see cref="PukDerivation"/>.
    /// </para>
    /// <para>
    /// The replacement is promoted here rather than on confirmation, because
    /// there is nobody to confirm: the machine is offline and may stay that way
    /// for a week. The value it replaces is kept as a candidate, so an unblock
    /// that failed at the card leaves a token that can still be rescued — see
    /// <see cref="Candidates"/> and <see cref="Refused"/>.
    /// </para>
    /// </remarks>
    public OfflineUnblockResponse? AnswerOffline(string challenge, string actor)
    {
        var read = OfflineUnblock.ReadChallenge(challenge);
        if (read is null)
        {
            throw new PukUnavailableException(
                "That is not a Blinky challenge, or it was mistyped. Ask for it again.");
        }

        var (serial, _) = read.Value;

        using var session = database.OpenSession();
        using var transaction = session.BeginTransaction();

        var token = session.Query<Token>().SingleOrDefault(t => t.Serial == serial);
        if (token is null)
        {
            return null;
        }

        if (token.PukState is CredentialSecretState.NotApplicable
            or CredentialSecretState.Disabled)
        {
            throw new PukUnavailableException(
                $"Token {serial} has no usable PUK ({token.PukState}).");
        }

        var current = Current(session, token);
        var next = PukDerivation.Next(current, challenge);

        // The new value becomes the one on record and the old one stays behind
        // it. Nothing here knows yet whether the card accepted the change.
        session.Save(Wrap(token, next, SecretKind.Puk));

        session.Save(new AuditEvent
        {
            OccurredAt = DateTime.UtcNow,
            EventType = "puk.disclosed",
            Actor = actor,
            SubjectType = nameof(Token),
            SubjectId = token.Id,
            TokenSerial = serial,
            Detail = $$"""{"reason":"offline-unblock","challenge":"{{challenge}}"}""",
        });

        token.PukState = CredentialSecretState.Set;
        token.UpdatedAt = DateTime.UtcNow;
        session.Update(token);

        transaction.Commit();

        logger.LogWarning("The PUK for token {Serial} was read out to {Actor} for an "
                          + "offline unblock", serial, actor);

        return new OfflineUnblockResponse(serial, OfflineUnblock.Response(current));
    }

    /// <summary>
    /// Takes back the last offline rotation, because the card never took it.
    /// </summary>
    /// <remarks>
    /// The helpdesk's undo. An offline unblock that failed at the card - a
    /// mistyped PIN, a token pulled out, a reader that stopped answering -
    /// leaves this escrow one step ahead of the token, and the next code read
    /// out would be refused as well. Somebody has to be able to say so.
    /// </remarks>
    public bool Refused(long serial)
    {
        using var session = database.OpenSession();
        using var transaction = session.BeginTransaction();

        var token = session.Query<Token>().SingleOrDefault(t => t.Serial == serial);
        if (token is null)
        {
            return false;
        }

        var newest = session.Query<SecretEnvelope>()
            .Where(e => e.Token.Id == token.Id && e.Kind == SecretKind.Puk)
            .OrderByDescending(e => e.CreatedAt)
            .FirstOrDefault();

        if (newest is null)
        {
            return false;
        }

        session.Delete(newest);

        // With nothing escrowed, this server holds no PUK for the token - and
        // saying "Set" would then be a claim about a value nobody has. Unknown
        // is the truth until a sweep asks the card, which happens on the next
        // poll and settles it either way.
        //
        // Found by using it: a rollback left the state saying Set, and the next
        // unblock was refused with "a PUK that Blinky did not set", on a token
        // sitting at the factory value the whole time.
        if (!session.Query<SecretEnvelope>()
                .Any(e => e.Token.Id == token.Id && e.Kind == SecretKind.Puk))
        {
            token.PukState = CredentialSecretState.Unknown;
            token.UpdatedAt = DateTime.UtcNow;
            session.Update(token);
        }

        session.Save(new AuditEvent
        {
            OccurredAt = DateTime.UtcNow,
            EventType = "puk.rollback",
            SubjectType = nameof(Token),
            SubjectId = token.Id,
            TokenSerial = serial,
            Detail = """{"reason":"the card refused the code that was read out"}""",
        });

        transaction.Commit();

        logger.LogWarning("The last PUK rotation for token {Serial} was rolled back", serial);

        return true;
    }

    /// <summary>
    /// The PUK the card is believed to hold.
    /// </summary>
    /// <remarks>
    /// Nothing escrowed and a card still reporting the factory value means the
    /// factory value: that is not a secret Blinky is keeping, it is one the
    /// vendor published, and pretending otherwise would make the first unblock
    /// of every new token fail.
    /// </remarks>
    /// <summary>The PUK the card is holding right now.</summary>
    /// <remarks>
    /// What the card says comes before what this server remembers, and the
    /// order used to be the other way round.
    ///
    /// An envelope records the PUK Blinky last set. PukState comes from the
    /// card's own metadata and is refreshed at every inventory. When the two
    /// disagree - the card reporting a factory PUK while an envelope says
    /// otherwise - the card is right, and the envelope is a memory of a card
    /// that has since been reset by something other than Blinky. `ykman piv
    /// reset` does exactly that, and so does anybody re-provisioning a token
    /// by hand.
    ///
    /// Believing the envelope there is not merely wrong, it is expensive: the
    /// value goes to the card, the card refuses it, and one of three PUK
    /// attempts is gone. Three of those and the PUK blocks, which is the thing
    /// this whole escrow exists to avoid.
    ///
    /// Seen on token 29051525, wiped between two enrolments: CHANGE PUK came
    /// back 63C2 with two attempts left.
    /// </remarks>
    private string Current(NHibernate.ISession session, Token token)
    {
        if (token.PukState == CredentialSecretState.Default)
        {
            return FactoryPuk;
        }

        var escrowed = session.Query<SecretEnvelope>()
            .Where(e => e.Token.Id == token.Id && e.Kind == SecretKind.Puk)
            .OrderByDescending(e => e.CreatedAt)
            .FirstOrDefault();

        if (escrowed is not null)
        {
            return Unwrap(escrowed);
        }

        throw new PukUnavailableException(
            $"Token {token.Serial} has a PUK that Blinky did not set and does not hold. "
            + "It cannot be unblocked from here.");
    }

    /// <summary>
    /// Eight digits from a cryptographic source, sampled without modulo bias.
    /// </summary>
    /// <remarks>
    /// Digits rather than the full byte range because the card is told this
    /// value as ASCII and other software reads PIV secrets back assuming
    /// numerals.
    /// </remarks>
    private static string Generate()
    {
        var digits = new char[PukLength];

        for (var i = 0; i < PukLength; i++)
        {
            digits[i] = (char)('0' + RandomNumberGenerator.GetInt32(0, 10));
        }

        return new string(digits);
    }

    private SecretEnvelope Wrap(Token token, string puk, SecretKind kind)
    {
        var nonce = RandomNumberGenerator.GetBytes(AesGcm.NonceByteSizes.MaxSize);
        var plaintext = Encoding.ASCII.GetBytes(puk);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[AesGcm.TagByteSizes.MaxSize];

        // The serial is authenticated but not encrypted, so a ciphertext moved
        // to another token's row fails to open rather than opening as somebody
        // else's PUK.
        var associated = $"puk|{token.Serial}";

        using var aes = new AesGcm(kek, tag.Length);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, Encoding.ASCII.GetBytes(associated));

        CryptographicOperations.ZeroMemory(plaintext);

        return new SecretEnvelope
        {
            Token = token,
            Kind = kind,
            KeyVersion = 1,
            Ciphertext = ciphertext,
            Nonce = nonce,
            Tag = tag,
            AssociatedData = associated,
            CreatedAt = DateTime.UtcNow,
        };
    }

    private string Unwrap(SecretEnvelope envelope)
    {
        var plaintext = new byte[envelope.Ciphertext.Length];

        using var aes = new AesGcm(kek, envelope.Tag.Length);

        aes.Decrypt(envelope.Nonce, envelope.Ciphertext, envelope.Tag, plaintext,
            Encoding.ASCII.GetBytes(envelope.AssociatedData));

        return Encoding.ASCII.GetString(plaintext);
    }
}

/// <summary>The current PUK, its replacement, and the row that tracks the swap.</summary>
public sealed record PukCheckout(Guid CheckoutId, string CurrentPuk, string NextPuk);

/// <summary>
/// The token cannot be unblocked, and the reason belongs in the answer.
/// </summary>
/// <remarks>
/// A refusal, not a fault: a Bio has no PUK by design and a token somebody else
/// personalised has one Blinky never held. Both are things an operator needs
/// told, not a 500.
/// </remarks>
public sealed class PukUnavailableException(string message) : Exception(message);
