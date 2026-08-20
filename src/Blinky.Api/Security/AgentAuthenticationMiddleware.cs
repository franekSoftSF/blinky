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
    /// Paths an operator reaches rather than an agent. They are exempt from
    /// mTLS because the caller is a person at a console, not a machine - and
    /// they carry their own check, because an unauthenticated write endpoint
    /// is not a smaller problem than the wrong kind of authentication.
    /// </summary>
    public static readonly string[] OperatorPaths =
    [
        "/api/jobs/inventory",
        "/api/jobs/enrol",

        // Both reached from a console, never from an agent: the machine whose
        // token is being rescued is the one that cannot call anybody.
        "/api/tokens/offline-unblock",
        "/api/tokens/puk/refused",
    ];

    public async Task InvokeAsync(HttpContext context, Database database)
    {
        var path = context.Request.Path;

        if (!path.StartsWithSegments("/api")
            || path.Equals(EnrolmentPath, StringComparison.OrdinalIgnoreCase)
            || OperatorPaths.Any(p => path.Equals(p, StringComparison.OrdinalIgnoreCase)))
        {
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
