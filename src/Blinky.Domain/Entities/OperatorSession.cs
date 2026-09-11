namespace Blinky.Domain.Entities;

/// <summary>
/// One operator, signed in, until something ends it.
/// </summary>
/// <remarks>
/// Server-side rather than a self-contained token, which patch 0053b argues is
/// the right trade for an administrative console: a signed token cannot be
/// withdrawn, so somebody removed at nine o'clock keeps working until their
/// token expires. A row can be deleted, which also makes "log out everywhere"
/// possible and "who is signed in right now" a question with an answer instead
/// of an estimate.
/// <para>
/// The cost is a database read per request. For a console used by a handful of
/// people that is an indexed lookup, and it buys the ability to cut somebody
/// off in the second you decide to.
/// </para>
/// </remarks>
public class OperatorSession
{
    public virtual Guid Id { get; protected set; }

    public virtual Guid OperatorAccountId { get; set; }

    /// <summary>
    /// SHA-256 of the token the client holds, hex.
    /// </summary>
    /// <remarks>
    /// Hashed because a table of session tokens in the clear is a table that
    /// impersonates every signed-in operator the moment anybody reads it - a
    /// backup, a support bundle, a query run by somebody entitled to query.
    /// <para>
    /// A plain hash rather than the password's PBKDF2, and that is deliberate
    /// rather than lazy: the reason a password needs a slow function is that
    /// people choose passwords a machine can guess. This token is 256 bits from
    /// the system's own generator, so there is nothing to guess and nothing for
    /// slowness to buy - while a slow function here would run on every single
    /// request.
    /// </para>
    /// </remarks>
    public virtual string TokenHash { get; set; } = string.Empty;

    /// <summary>
    /// Where it was signed in from, for the person reading the session list.
    /// </summary>
    /// <remarks>
    /// Not a security control - an address is trivially wrong behind a proxy
    /// and trivially shared on a network. It is here so that somebody looking
    /// at four live sessions has something to recognise their own by before
    /// ending the other three.
    /// </remarks>
    public virtual string? CreatedFrom { get; set; }

    public virtual DateTime CreatedAt { get; set; }

    public virtual DateTime LastSeenAt { get; set; }

    /// <summary>
    /// When it dies from disuse. Pushed forward by activity.
    /// </summary>
    public virtual DateTime IdleExpiresAt { get; set; }

    /// <summary>
    /// When it dies regardless. Never pushed forward.
    /// </summary>
    /// <remarks>
    /// Without this a console left open in a browser tab is a credential with
    /// no end date, because every poll the page makes counts as activity. The
    /// idle timeout protects an unattended desk; this one protects against the
    /// session simply never stopping.
    /// </remarks>
    public virtual DateTime AbsoluteExpiresAt { get; set; }

    public virtual DateTime? RevokedAt { get; set; }

    /// <summary>
    /// Why it was ended, for the audit trail. Null while it is alive.
    /// </summary>
    public virtual string? RevokedReason { get; set; }
}
