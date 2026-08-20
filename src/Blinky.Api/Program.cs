using Blinky.Api.Agents;
using Blinky.Api.Persistence;
using Blinky.Api.Jobs;
using Blinky.Api.Security;
using Blinky.Api.Tokens;
using Blinky.Contracts;
using Blinky.Domain.Entities;
using Blinky.Infrastructure;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

builder.Host.UseSerilog((context, services, configuration) => configuration
    .ReadFrom.Configuration(context.Configuration)
    .ReadFrom.Services(services)
    .Enrich.FromLogContext());

var connectionString = builder.Configuration.GetConnectionString("Blinky") ?? string.Empty;
builder.Services.AddSingleton(new Database(connectionString));

builder.Services.AddSingleton(_ => AgentCertificateAuthority.Load(
    builder.Configuration["Blinky:AgentCa:CertificatePath"] ?? "/etc/blinky/certs/agent-ca.crt",
    builder.Configuration["Blinky:AgentCa:KeyPath"] ?? "/etc/blinky/certs/agent-ca.key",
    TimeSpan.FromDays(builder.Configuration.GetValue("Blinky:AgentCa:LifetimeDays", 90))));

builder.Services.AddSingleton<TokenInventoryService>();
builder.Services.AddSingleton<JobService>();

builder.Services.AddSingleton(services => new AgentEnrolmentService(
    services.GetRequiredService<Database>(),
    services.GetRequiredService<AgentCertificateAuthority>(),
    builder.Configuration["Blinky:Enrolment:BootstrapToken"] ?? string.Empty,
    services.GetRequiredService<ILogger<AgentEnrolmentService>>()));

var app = builder.Build();

// Compare the mappings against the live schema once, at start. This logs and
// continues on purpose: a missing column should produce one readable line while
// the container comes up, not a restart loop with no explanation. See
// docs/02-data-model.md.
var schema = string.IsNullOrWhiteSpace(connectionString)
    ? new SchemaValidationResult(false, "no connection string configured")
    : SchemaValidator.Validate(BlinkySessionFactory.BuildConfiguration(connectionString));

if (schema.IsValid)
{
    app.Logger.LogInformation("Schema validation: {Summary}", schema.Summary);
}
else
{
    app.Logger.LogError("Schema validation FAILED: {Summary}", schema.Summary);
}

app.UseSerilogRequestLogging();
app.UseMiddleware<AgentAuthenticationMiddleware>();

app.MapGet("/health", () => Results.Ok(new
{
    status = "ok",
    service = "Blinky.Api",
    protocol = Blinky.Contracts.Protocol.SchemaVersion,
    schema = new { valid = schema.IsValid, detail = schema.Summary },
}));

// The only unauthenticated endpoint in the API: an agent cannot present a
// certificate it has not been issued yet. See docs/05-agent-protocol.md.
app.MapPost(AgentAuthenticationMiddleware.EnrolmentPath,
    (EnrolmentRequest request, AgentEnrolmentService enrolment) =>
    {
        var result = enrolment.Enrol(request);

        return result.Outcome switch
        {
            EnrolmentOutcome.Issued => Results.Ok(result.Response),
            EnrolmentOutcome.InvalidToken =>
                Results.Json(new { error = result.Message }, statusCode: 401),
            EnrolmentOutcome.InvalidRequest =>
                Results.Json(new { error = result.Message }, statusCode: 400),
            _ => Results.Json(new { error = result.Message }, statusCode: 403),
        };
    });

// Who the edge says is calling, and which agent row that certificate belongs
// to. Useful on its own, and the first thing to check when an agent is
// mysteriously collecting 401s.
app.MapGet("/api/agents/whoami", (HttpContext context) =>
{
    var certificate = ClientCertificate.From(context.Request)!;
    var agent = (Agent)context.Items["agent"]!;

    return Results.Ok(new
    {
        agentId = agent.Id,
        agent.Hostname,
        agent.Domain,
        state = agent.State.ToString(),
        subject = certificate.Subject,
        issuer = certificate.Issuer,
        thumbprint = certificate.Thumbprint,
        notAfter = certificate.NotAfter,
    });
});

// What an agent found in a reader. Facts in, judgement here - see
// TokenInventoryService.
app.MapPost("/api/tokens/inventory",
    (TokenInventoryReport report, TokenInventoryService inventory) =>
    {
        if (!Protocol.IsSupported(report.SchemaVersion))
        {
            return Results.Json(new
            {
                error = $"schema version {report.SchemaVersion} is not supported",
                supported = new
                {
                    minimum = Protocol.MinimumSupportedVersion,
                    maximum = Protocol.MaximumSupportedVersion,
                },
            }, statusCode: 400);
        }

        return Results.Ok(inventory.Accept(report));
    });

// An agent asking for work. Returns 204 when there is none, which is the
// normal answer most of the time.
app.MapGet("/api/jobs/next", (HttpContext context, JobService jobs) =>
{
    var agent = (Agent)context.Items["agent"]!;
    var claim = jobs.Claim(agent.Id);

    return claim is null ? Results.NoContent() : Results.Ok(claim);
});

app.MapPost("/api/jobs/{id:guid}/progress",
    (Guid id, JobProgress progress, HttpContext context, JobService jobs) =>
    {
        var agent = (Agent)context.Items["agent"]!;

        return jobs.Report(agent.Id, progress with { JobId = id })
            ? Results.NoContent()
            : Results.Json(new { error = "this job is not yours to report on" },
                statusCode: 403);
    });

app.MapPost("/api/jobs/{id:guid}/result",
    (Guid id, JobResult result, HttpContext context, JobService jobs) =>
    {
        var agent = (Agent)context.Items["agent"]!;

        return jobs.Complete(agent.Id, result with { JobId = id })
            ? Results.NoContent()
            : Results.Json(new { error = "this job is not yours to finish" }, statusCode: 403);
    });

// Creating work belongs to an operator, never to an agent: the API creates
// jobs on request and never decides on its own that work exists.
//
// Until RBAC arrives in 0053 the operator proves themselves with a shared
// token. That is a stop-gap and is named as one - but an unauthenticated write
// endpoint would not have been the smaller compromise.
var operatorToken = builder.Configuration["Blinky:Operator:Token"] ?? string.Empty;

app.MapPost("/api/jobs/inventory",
    (InventoryJobRequest request, HttpContext context, JobService jobs) =>
    {
        if (!IsOperator(context, operatorToken))
        {
            return Results.Json(new { error = "an operator token is required" },
                statusCode: 401);
        }

        var key = $"inventory:{request.AgentId}:{request.Reason ?? "manual"}";

        var (job, created) = jobs.Create(JobType.Inventory, key,
            id => JobEnvelope.Inventory(id, key, DateTimeOffset.UtcNow.AddHours(1)),
            request.AgentId);

        return Results.Ok(new { job.Id, created, state = job.State.ToString() });
    });

app.MapPost("/api/agents/{id:guid}/heartbeat",
    (Guid id, HeartbeatRequest request, HttpContext context, Database database) =>
    {
        var caller = (Agent)context.Items["agent"]!;
        if (caller.Id != id)
        {
            // An agent speaks only for itself, whatever id it puts in the URL.
            return Results.Json(new { error = "the certificate belongs to a different agent" },
                statusCode: 403);
        }

        using var session = database.OpenSession();
        using var transaction = session.BeginTransaction();

        foreach (var card in request.Unsupported ?? [])
        {
            // Not stored: the identity model is the token's serial, and a card
            // that answers no Yubico instruction has none. Visible in the log
            // and in the heartbeat is what stops it looking like a dead agent.
            app.Logger.LogInformation(
                "Agent {AgentId} has an unmanageable card in {Reader}: {Reason}",
                id, card.ReaderName, card.Reason);
        }

        var agent = session.Get<Agent>(id);
        agent.Version = request.Version;
        agent.LastHeartbeatAt = DateTime.UtcNow;
        agent.UpdatedAt = DateTime.UtcNow;
        session.Update(agent);

        transaction.Commit();

        return Results.Ok(new
        {
            protocol = Blinky.Contracts.Protocol.SchemaVersion,
            supported = new
            {
                minimum = Blinky.Contracts.Protocol.MinimumSupportedVersion,
                maximum = Blinky.Contracts.Protocol.MaximumSupportedVersion,
            },
            pollIntervalSeconds = 60,
        });
    });

app.Run();

/// <summary>
/// Constant-time comparison of the stand-in operator token. Returning early on
/// the first wrong byte would leak the prefix to anything that can time a
/// request.
/// </summary>
static bool IsOperator(HttpContext context, string expected)
{
    if (string.IsNullOrEmpty(expected))
    {
        return false;
    }

    var presented = context.Request.Headers["X-Blinky-Operator"].ToString();

    return !string.IsNullOrEmpty(presented)
           && System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
               System.Text.Encoding.UTF8.GetBytes(presented),
               System.Text.Encoding.UTF8.GetBytes(expected));
}

/// <summary>What an agent reports when it checks in.</summary>
/// <summary>Asks for one token inventory pass on one agent.</summary>
internal sealed record InventoryJobRequest(Guid AgentId, string? Reason);

internal sealed record HeartbeatRequest(
    string? Version,
    string[]? Readers,
    UnsupportedCardReport[]? Unsupported);
