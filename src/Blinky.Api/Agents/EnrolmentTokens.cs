using Blinky.Api.Persistence;
using Blinky.Domain.Entities;
using NHibernate.Linq;

namespace Blinky.Api.Agents;

/// <summary>What happened when a token was presented.</summary>
public enum TokenOutcome
{
    /// <summary>Spent. The use is counted and committed.</summary>
    Accepted,

    /// <summary>
    /// Refused, and deliberately without saying why.
    /// </summary>
    /// <remarks>
    /// One answer for "no such token", "expired", "used up", "revoked" and
    /// "wrong domain". The caller is unauthenticated, so telling it which of
    /// those applies turns the endpoint into a way to find out which tokens
    /// exist and what they are for.
    /// </remarks>
    Refused,
}

/// <summary>
/// Creating, listing, withdrawing and spending enrolment tokens.
/// </summary>
/// <remarks>
/// The rules live here rather than in the endpoints because two different
/// callers spend a token - a workstation agent and an ADCS connector - and the
/// counting has to happen exactly once, inside the transaction that issues the
/// certificate. A check in one handler and a decrement in another is how a
/// token with one use left enrols two machines.
/// </remarks>
public sealed class EnrolmentTokens(Database database, Func<DateTime> clock, ILogger<EnrolmentTokens> logger)
{
    /// <summary>
    /// The longest a token may live.
    /// </summary>
    /// <remarks>
    /// A year, not because a year is safe, but because "never" has to be asked
    /// for in words. The console offers days; the API refuses more than this.
    /// </remarks>
    public static readonly TimeSpan LongestLife = TimeSpan.FromDays(365);

    public (EnrolmentToken Row, string Token) Create(
        string name,
        EnrolmentPurpose purpose,
        TimeSpan? validFor,
        int? maxUses,
        string? allowedDomain,
        string createdBy)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        if (validFor is { } life && (life <= TimeSpan.Zero || life > LongestLife))
        {
            throw new ArgumentOutOfRangeException(nameof(validFor),
                $"a token lives between a moment and {LongestLife.TotalDays:0} days");
        }

        if (maxUses is <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxUses), "a token with no uses is not a token");
        }

        var now = clock();
        var (token, hash) = EnrolmentToken.Generate();

        var row = new EnrolmentToken
        {
            Name = name.Trim(),
            Purpose = purpose,
            TokenHash = hash,
            ExpiresAt = validFor is null ? null : now.Add(validFor.Value),
            MaxUses = maxUses,
            AllowedDomain = string.IsNullOrWhiteSpace(allowedDomain) ? null : allowedDomain.Trim(),
            CreatedBy = createdBy,
            CreatedAt = now,
        };

        using var session = database.OpenSession();
        using var transaction = session.BeginTransaction();

        session.Save(row);
        transaction.Commit();

        logger.LogInformation(
            "Enrolment token {Name} created by {Operator} for {Purpose}, expires {Expires}, uses {Uses}",
            row.Name, createdBy, purpose,
            row.ExpiresAt?.ToString("u") ?? "never", maxUses?.ToString() ?? "unlimited");

        return (row, token);
    }

    public IReadOnlyList<EnrolmentToken> All()
    {
        using var session = database.OpenSession();

        return session.Query<EnrolmentToken>()
            .OrderByDescending(t => t.CreatedAt)
            .ToList();
    }

    /// <summary>Withdraws a token. Idempotent: revoking a revoked token is a success.</summary>
    public EnrolmentToken? Revoke(Guid id, string by, string? reason)
    {
        using var session = database.OpenSession();
        using var transaction = session.BeginTransaction();

        var row = session.Get<EnrolmentToken>(id);

        if (row is null)
        {
            transaction.Commit();
            return null;
        }

        if (row.RevokedAt is null)
        {
            row.RevokedAt = clock();
            row.RevokedBy = by;
            row.RevokedReason = reason;
            session.Update(row);
        }

        transaction.Commit();

        return row;
    }

    /// <summary>
    /// Whether a token may fetch its machine's installer: right purpose, not
    /// withdrawn, not expired - and not spent by asking (0110).
    /// </summary>
    /// <remarks>
    /// Uses are not counted, because downloading is not joining: the install script
    /// fetches the package with the same token the agent enrols with a minute later,
    /// and a one-use token spent on the download would refuse the enrolment. A token
    /// whose uses are gone still downloads until it expires, which is what lets the
    /// same token upgrade a connector; the MSI is not a secret, and the token only
    /// keeps a deployment's packages from being public.
    /// </remarks>
    public bool Admits(string? presented, EnrolmentPurpose purpose)
    {
        if (string.IsNullOrWhiteSpace(presented))
        {
            return false;
        }

        var hash = EnrolmentToken.Fingerprint(presented);
        var now = clock();

        using var session = database.OpenSession();
        var row = session.Query<EnrolmentToken>().SingleOrDefault(t => t.TokenHash == hash);

        return row is not null
               && row.Purpose == purpose
               && row.RevokedAt is null
               && (row.ExpiresAt is null || row.ExpiresAt > now);
    }

    /// <summary>
    /// Spends one use of a token, or refuses.
    /// </summary>
    /// <remarks>
    /// The use is counted before the certificate is issued and in its own
    /// transaction. Counting afterwards would mean a token with one use left
    /// could be presented twice in parallel and spend itself twice, which is
    /// precisely the limit somebody chose it for.
    /// </remarks>
    public (TokenOutcome Outcome, EnrolmentToken? Token) Spend(
        string? presented,
        EnrolmentPurpose purpose,
        string? domain)
    {
        if (string.IsNullOrWhiteSpace(presented))
        {
            return (TokenOutcome.Refused, null);
        }

        var hash = EnrolmentToken.Fingerprint(presented);
        var now = clock();

        using var session = database.OpenSession();
        using var transaction = session.BeginTransaction();

        var row = session.Query<EnrolmentToken>().SingleOrDefault(t => t.TokenHash == hash);
        var refusal = row is null ? "no such token" : row.Refusal(purpose, domain, now);

        if (refusal is not null)
        {
            transaction.Commit();

            // The reason is logged and never returned: the caller is
            // unauthenticated, and "expired" told back is a way to learn which
            // tokens exist.
            logger.LogWarning("Enrolment refused: {Reason}", refusal);

            return (TokenOutcome.Refused, null);
        }

        row!.Uses++;
        session.Update(row);
        transaction.Commit();

        return (TokenOutcome.Accepted, row);
    }
}
