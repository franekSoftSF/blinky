using Blinky.Api.Agents;
using Blinky.Api.Persistence;
using Blinky.Api.Security;
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

/// <summary>What an agent reports when it checks in.</summary>
internal sealed record HeartbeatRequest(string? Version, string[]? Readers);
