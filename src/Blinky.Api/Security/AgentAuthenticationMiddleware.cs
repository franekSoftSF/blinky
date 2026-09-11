using Blinky.Api.Persistence;
using Blinky.Domain.Entities;
using NHibernate.Linq;

namespace Blinky.Api.Security;

/// <summary>
/// Requires a verified client certificate on the agent API, and matches it to a
/// registered agent.
/// </summary>
/// <remarks>
/// The enforcement is here rather than only at the edge. nginx checks the
/// certificate against the CA; only the database can say whether that
/// certificate belongs to an agent that still exists and is not suspended - and
/// a revoked agent must stop working without waiting for a proxy reload.
/// </remarks>
public sealed class AgentAuthenticationMiddleware(RequestDelegate next, ILogger<AgentAuthenticationMiddleware> logger)
{
    /// <summary>
    /// The one unauthenticated endpoint. It has to be: an agent cannot present
    /// a certificate it has not been issued yet.
    /// </summary>
    public const string EnrolmentPath = "/api/agents/enroll";

    /// <summary>
    /// Routes an operator reaches rather than an agent. They are exempt from
    /// mTLS because the caller is a person at a console, not a machine - and
    /// they carry their own check, because an unauthenticated write endpoint
    /// is not a smaller problem than the wrong kind of authentication.
    /// </summary>
    /// <remarks>
    /// This has to name every route whose handler calls IsOperator, and the two
    /// drifted: twelve of eighteen operator endpoints were missing, so the
    /// console was refused its own API with "a verified client certificate is
    /// required" - an answer about certificates for a request that never
    /// involved one. Every status card in the console read as a broken
    /// deployment instead.
    ///
    /// Missing an entry fails closed, which is the right direction, but it
    /// fails in a way that reads as an outage rather than as a missing line
    /// here. Whoever adds an operator endpoint adds it here too; the tests in
    /// OperatorRouteTests hold that.
    /// </remarks>
    public static readonly string[] OperatorPaths =
    [
        "/api/console/overview",
        "/api/system/status",

        "/api/jobs/inventory",
        "/api/jobs/enrol",
        "/api/jobs/recycle",

        // Both reached from a console, never from an agent: the machine whose
        // token is being rescued is the one that cannot call anybody.
        "/api/tokens/offline-unblock",
        "/api/tokens/puk/refused",

        "/api/directory/test",
        "/api/directory/test-resolve",
        "/api/directory/test-write-access",
        "/api/directory/users",

        // Signing in cannot require being signed in, and these carry their own
        // checks: a password, a code, or a session token.
        "/api/auth/sign-in",
        "/api/auth/totp/enrol",
        "/api/auth/password",
        "/api/auth/me",
        "/api/auth/sign-out",
        "/api/auth/sessions",
        "/api/auth/sessions/revoke-all",

        "/api/profiles",
        "/api/cardholders",

        // Route patterns, not paths. A help desk request arrives as
        // /api/tokens/12345/helpdesk and matches nothing written literally,
        // which is why these could not be listed at all before the comparison
        // below started asking the router what it matched.
        "/api/tokens/{serial:long}/helpdesk",
        "/api/tokens/{serial:long}/block",
        "/api/tokens/{serial:long}/unblock",
        "/api/credentials/{id:guid}/suspend",
        "/api/credentials/{id:guid}/revoke",
    ];

    private static readonly OperatorSessions Sessions = new(() => DateTime.UtcNow);

    /// <summary>
    /// Puts the signed-in account in <c>context.Items["operator"]</c> when the
    /// request carries a live session, and leaves nothing there otherwise.
    /// </summary>
    /// <remarks>
    /// Resolved once here rather than in every handler, which is also what
    /// makes ending a session take effect on the next request instead of
    /// whenever a self-contained token would have expired.
    /// <para>
    /// Swallows its own failures on purpose. This runs ahead of endpoints with
    /// their own authentication - signing in, most obviously - so a database
    /// that is briefly unreachable should let those refuse for their own
    /// reasons rather than turn every operator route into an error about
    /// sessions.
    /// </para>
    /// </remarks>
    private void ResolveSession(HttpContext context, Database database)
    {
        var authorization = context.Request.Headers.Authorization.ToString();
        var presented = authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
            ? authorization["Bearer ".Length..].Trim()
            : context.Request.Headers["X-Blinky-Session"].ToString().Trim();

        if (string.IsNullOrEmpty(presented))
        {
            return;
        }

        try
        {
            using var session = database.OpenSession();
            using var transaction = session.BeginTransaction();

            var fingerprint = SessionTokens.Fingerprint(presented);
            var row = session.Query<OperatorSession>()
                .FirstOrDefault(s => s.TokenHash == fingerprint);

            var check = Sessions.Check(row);

            if (!check.Accepted)
            {
                transaction.Commit();
                return;
            }

            var account = session.Get<OperatorAccount>(check.Session!.OperatorAccountId);

            // An account disabled while somebody is signed in stops here, for
            // the same reason the session itself can be ended.
            if (account is not null && account.State == Blinky.Domain.OperatorAccountState.Active)
            {
                context.Items["operator"] = account;
                session.Update(check.Session);
            }

            transaction.Commit();
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Could not resolve a session token; falling back.");
        }
    }

    public async Task InvokeAsync(HttpContext context, Database database)
    {
        var path = context.Request.Path;

        // What the router matched, not what the caller typed. A parameterised
        // route - /api/tokens/{serial:long}/block - arrives as a path with a
        // number in it and can never be compared against the pattern as
        // written, so the list above could only ever hold literal routes.
        // Falls back to the raw path when nothing matched, which keeps an
        // unroutable request on the guarded side.
        var pattern = (context.GetEndpoint() as RouteEndpoint)?.RoutePattern.RawText;

        bool IsOperatorRoute() => OperatorPaths.Any(p =>
            string.Equals(p, pattern, StringComparison.OrdinalIgnoreCase)
            || path.Equals(p, StringComparison.OrdinalIgnoreCase));

        if (!path.StartsWithSegments("/api")
            || path.Equals(EnrolmentPath, StringComparison.OrdinalIgnoreCase)
            || IsOperatorRoute())
        {
            // Resolved here so the handlers do not each have to, and so a
            // session that has been ended stops working on the next request
            // rather than at the end of its own lifetime. Absent or invalid
            // leaves nothing behind and the handler falls back to the shared
            // token, which is what still carries the scripts until 0053e.
            ResolveSession(context, database);

            await next(context);
            return;
        }

        var certificate = ClientCertificate.From(context.Request);
        if (certificate is null)
        {
            await Deny(context, "a verified client certificate is required");
            return;
        }

        using var session = database.OpenSession();
        var agent = session.Query<Agent>()
            .SingleOrDefault(a => a.ClientCertificateThumbprint == certificate.Thumbprint);

        if (agent is null)
        {
            logger.LogWarning("Rejected a certificate not held by any agent: {Thumbprint}",
                certificate.Thumbprint);

            await Deny(context, "this certificate does not belong to a registered agent");
            return;
        }

        if (agent.State is not Blinky.Domain.AgentState.Enrolled)
        {
            await Deny(context, $"the agent is {agent.State}");
            return;
        }

        context.Items["agent"] = agent;
        await next(context);
    }

    private static Task Deny(HttpContext context, string reason)
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        return context.Response.WriteAsJsonAsync(new { error = reason });
    }
}
