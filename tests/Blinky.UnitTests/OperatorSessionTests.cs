using Blinky.Api.Security;
using Blinky.Domain.Entities;

namespace Blinky.UnitTests;

/// <summary>
/// A session that can be ended - patch 0053b.
/// </summary>
/// <remarks>
/// The argument the patch makes is that a self-contained token cannot be
/// withdrawn, so somebody removed at nine o'clock keeps working until it
/// expires. These cases are that argument as checks: revocation takes effect
/// on the next request, two clocks bound the session from different
/// directions, and the stored form cannot be turned back into a credential.
/// </remarks>
public class OperatorSessionTests
{
    private DateTime now = new(2026, 9, 11, 9, 0, 0, DateTimeKind.Utc);

    private OperatorSessions Sessions() => new(() => now);

    [Fact]
    public void The_database_holds_a_fingerprint_and_not_the_token()
    {
        var (session, token) = Sessions().Issue(Guid.NewGuid(), "172.16.5.51");

        Assert.NotEqual(token, session.TokenHash);
        Assert.DoesNotContain(token, session.TokenHash, StringComparison.Ordinal);
        Assert.Equal(64, session.TokenHash.Length);
        Assert.Equal(SessionTokens.Fingerprint(token), session.TokenHash);

        // And the same token always finds the same row, or nobody could sign in
        // twice with one session.
        Assert.Equal(session.TokenHash, SessionTokens.Fingerprint(token));
    }

    [Fact]
    public void Two_tokens_are_never_the_same()
    {
        var issued = Enumerable.Range(0, 200)
            .Select(_ => Sessions().Issue(Guid.NewGuid(), null).Token)
            .ToList();

        Assert.Equal(issued.Count, issued.Distinct(StringComparer.Ordinal).Count());
    }

    /// <summary>
    /// Revocation is the whole point, so it takes effect on the next request.
    /// </summary>
    [Fact]
    public void A_revoked_session_stops_immediately()
    {
        var sessions = Sessions();
        var (session, _) = sessions.Issue(Guid.NewGuid(), null);

        Assert.True(sessions.Check(session).Accepted);

        sessions.Revoke(session, "signed out");

        var refused = sessions.Check(session);

        Assert.False(refused.Accepted);
        Assert.Equal(SessionRefusal.Revoked, refused.Refusal);
    }

    /// <summary>
    /// The first reason a session ended is the one that is kept.
    /// </summary>
    /// <remarks>
    /// A later revocation would overwrite why it actually happened - "an
    /// administrator withdrew this" - with why somebody tidied up afterwards.
    /// </remarks>
    [Fact]
    public void Ending_an_ended_session_does_not_rewrite_why()
    {
        var sessions = Sessions();
        var (session, _) = sessions.Issue(Guid.NewGuid(), null);

        sessions.Revoke(session, "administrator withdrew access");
        var when = session.RevokedAt;

        now = now.AddHours(1);
        sessions.Revoke(session, "expired cleanup");

        Assert.Equal("administrator withdrew access", session.RevokedReason);
        Assert.Equal(when, session.RevokedAt);
    }

    [Fact]
    public void Log_out_everywhere_ends_every_live_session_and_counts_them()
    {
        var sessions = Sessions();
        var account = Guid.NewGuid();
        var all = Enumerable.Range(0, 4)
            .Select(_ => sessions.Issue(account, null).Session).ToList();

        sessions.Revoke(all[0], "signed out on that machine");

        Assert.Equal(3, sessions.RevokeAll(all, "password changed"));
        Assert.All(all, s => Assert.NotNull(s.RevokedAt));
        Assert.Equal("signed out on that machine", all[0].RevokedReason);
    }

    [Fact]
    public void Disuse_ends_it()
    {
        var sessions = Sessions();
        var (session, _) = sessions.Issue(Guid.NewGuid(), null);

        now = now.Add(OperatorSessions.IdleTimeout).AddSeconds(1);

        Assert.Equal(SessionRefusal.Idle, sessions.Check(session).Refusal);
    }

    [Fact]
    public void Activity_moves_the_idle_window()
    {
        var sessions = Sessions();
        var (session, _) = sessions.Issue(Guid.NewGuid(), null);

        for (var i = 0; i < 6; i++)
        {
            now = now.AddMinutes(20);
            Assert.True(sessions.Check(session).Accepted, $"still live after {(i + 1) * 20} minutes");
        }

        Assert.Equal(now, session.LastSeenAt);
    }

    /// <summary>
    /// Being busy does not make a session immortal.
    /// </summary>
    /// <remarks>
    /// The failure this prevents is a console left open in a tab: every poll
    /// the page makes counts as activity, so without an absolute limit the
    /// idle timeout silently stops meaning anything.
    /// </remarks>
    [Fact]
    public void A_busy_session_still_ends_at_its_absolute_limit()
    {
        var sessions = Sessions();
        var (session, _) = sessions.Issue(Guid.NewGuid(), null);

        // Used constantly for the whole of its life.
        for (var minutes = 0; minutes < OperatorSessions.AbsoluteLifetime.TotalMinutes; minutes += 10)
        {
            now = now.AddMinutes(10);
            sessions.Check(session);
        }

        now = now.AddMinutes(1);

        Assert.Equal(SessionRefusal.Expired, sessions.Check(session).Refusal);
    }

    /// <summary>
    /// The idle window never reaches past the absolute one.
    /// </summary>
    [Fact]
    public void The_idle_window_is_capped_by_the_absolute_one()
    {
        var sessions = Sessions();
        var (session, _) = sessions.Issue(Guid.NewGuid(), null);

        // Close to the end of its life and still in use, which is the only way
        // to reach the cap: a session that went idle first is refused before
        // anything gets extended.
        now = session.AbsoluteExpiresAt.AddMinutes(-5);
        session.IdleExpiresAt = now.AddMinutes(1);

        Assert.True(sessions.Check(session).Accepted);

        // Thirty minutes from now would run past the absolute end, so it stops
        // there instead.
        Assert.Equal(session.AbsoluteExpiresAt, session.IdleExpiresAt);
    }

    [Fact]
    public void An_unknown_token_is_refused_without_a_row()
    {
        var check = Sessions().Check(null);

        Assert.False(check.Accepted);
        Assert.Equal(SessionRefusal.Unknown, check.Refusal);
    }

    /// <summary>
    /// A session that was ended and then expired reports that it was ended.
    /// </summary>
    /// <remarks>
    /// The operator who pressed the button needs to see it took effect.
    /// "Expired" would suggest it ran its course on its own.
    /// </remarks>
    [Fact]
    public void Revocation_is_reported_before_expiry()
    {
        var sessions = Sessions();
        var (session, _) = sessions.Issue(Guid.NewGuid(), null);

        sessions.Revoke(session, "administrator withdrew access");
        now = now.Add(OperatorSessions.AbsoluteLifetime).AddHours(1);

        Assert.Equal(SessionRefusal.Revoked, sessions.Check(session).Refusal);
    }

    [Fact]
    public void The_session_list_shows_what_a_person_would_call_live()
    {
        var sessions = Sessions();
        var account = Guid.NewGuid();

        var live = sessions.Issue(account, "172.16.5.51").Session;
        var ended = sessions.Issue(account, "172.16.5.52").Session;
        var stale = sessions.Issue(account, "172.16.5.53").Session;

        sessions.Revoke(ended, "signed out");
        stale.IdleExpiresAt = now.AddMinutes(-1);

        var shown = sessions.Live([live, ended, stale]).ToList();

        Assert.Single(shown);
        Assert.Equal("172.16.5.51", shown[0].CreatedFrom);
    }
}
