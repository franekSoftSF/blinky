using Blinky.Domain.Entities;

namespace Blinky.Api.Security;

/// <summary>Why a presented session token did not work.</summary>
public enum SessionRefusal
{
    /// <summary>No row holds that fingerprint.</summary>
    Unknown,

    /// <summary>Somebody ended it - the operator, an administrator, or a sign-out.</summary>
    Revoked,

    /// <summary>Nothing used it for long enough.</summary>
    Idle,

    /// <summary>It reached the end of its life, however busy it was.</summary>
    Expired,
}

public sealed record SessionCheck(OperatorSession? Session, SessionRefusal? Refusal)
{
    public bool Accepted => Session is not null && Refusal is null;
}

/// <summary>
/// Issuing, checking and ending console sessions.
/// </summary>
/// <remarks>
/// Holds no storage of its own: the caller supplies the row it found and
/// persists whatever this changes. That keeps the rules - two clocks, an
/// explicit revocation, an idle window that moves and an absolute one that does
/// not - testable without a database, which is the half worth testing.
/// </remarks>
public sealed class OperatorSessions(Func<DateTime> clock)
{
    /// <summary>
    /// How long an unused session survives.
    /// </summary>
    /// <remarks>
    /// Half an hour. Long enough that reading a long audit view does not end
    /// it, short enough that a console left open at an unattended desk is not
    /// a standing invitation.
    /// </remarks>
    public static readonly TimeSpan IdleTimeout = TimeSpan.FromMinutes(30);

    /// <summary>
    /// How long a session survives no matter how busy it is.
    /// </summary>
    /// <remarks>
    /// Twelve hours, so a session cannot outlive the working day that started
    /// it. Without an absolute limit a page that polls keeps its own credential
    /// alive forever, and the idle timeout silently stops meaning anything.
    /// </remarks>
    public static readonly TimeSpan AbsoluteLifetime = TimeSpan.FromHours(12);

    /// <summary>
    /// A new session, and the token to hand back exactly once.
    /// </summary>
    public (OperatorSession Session, string Token) Issue(Guid accountId, string? createdFrom)
    {
        var now = clock();
        var token = SessionTokens.New();

        var session = new OperatorSession
        {
            OperatorAccountId = accountId,
            TokenHash = SessionTokens.Fingerprint(token),
            CreatedFrom = createdFrom,
            CreatedAt = now,
            LastSeenAt = now,
            IdleExpiresAt = now.Add(IdleTimeout),
            AbsoluteExpiresAt = now.Add(AbsoluteLifetime),
        };

        return (session, token);
    }

    /// <summary>
    /// Whether a session is usable now, and if so, moves its idle window.
    /// </summary>
    /// <remarks>
    /// Revocation is checked before either clock. A session that was ended and
    /// then expired should say it was ended: the operator who pressed the
    /// button needs to see it took effect, and "expired" would suggest it ran
    /// its course on its own.
    /// </remarks>
    public SessionCheck Check(OperatorSession? session)
    {
        if (session is null)
        {
            return new SessionCheck(null, SessionRefusal.Unknown);
        }

        if (session.RevokedAt is not null)
        {
            return new SessionCheck(session, SessionRefusal.Revoked);
        }

        var now = clock();

        if (session.AbsoluteExpiresAt <= now)
        {
            return new SessionCheck(session, SessionRefusal.Expired);
        }

        if (session.IdleExpiresAt <= now)
        {
            return new SessionCheck(session, SessionRefusal.Idle);
        }

        session.LastSeenAt = now;

        // Moved forward, and never past the absolute end. Otherwise a busy
        // session would quietly extend the limit that exists precisely so that
        // being busy is not enough.
        var extended = now.Add(IdleTimeout);
        session.IdleExpiresAt = extended > session.AbsoluteExpiresAt
            ? session.AbsoluteExpiresAt
            : extended;

        return new SessionCheck(session, null);
    }

    /// <summary>
    /// Ends one session, with a reason that outlives it.
    /// </summary>
    /// <remarks>
    /// Marked rather than deleted. "Who was signed in when this happened" is a
    /// question the audit view has to answer afterwards, and a deleted row
    /// answers nothing.
    /// </remarks>
    public void Revoke(OperatorSession session, string reason)
    {
        ArgumentNullException.ThrowIfNull(session);

        // Already ended stays ended, with its first reason. A later one would
        // overwrite why it actually happened with why somebody tidied up.
        if (session.RevokedAt is not null)
        {
            return;
        }

        session.RevokedAt = clock();
        session.RevokedReason = reason;
    }

    /// <summary>
    /// Ends all of them - "log out everywhere", and what happens when an
    /// account is disabled or its password changes.
    /// </summary>
    public int RevokeAll(IEnumerable<OperatorSession> sessions, string reason)
    {
        ArgumentNullException.ThrowIfNull(sessions);

        var ended = 0;

        foreach (var session in sessions)
        {
            if (session.RevokedAt is null)
            {
                Revoke(session, reason);
                ended++;
            }
        }

        return ended;
    }

    /// <summary>
    /// The ones a person would recognise as live, for the session list.
    /// </summary>
    public IEnumerable<OperatorSession> Live(IEnumerable<OperatorSession> sessions)
    {
        var now = clock();

        return sessions.Where(s => s.RevokedAt is null
                                   && s.AbsoluteExpiresAt > now
                                   && s.IdleExpiresAt > now);
    }
}
