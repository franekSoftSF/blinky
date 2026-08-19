using Serilog;

var builder = WebApplication.CreateBuilder(args);

builder.Host.UseSerilog((context, services, configuration) => configuration
    .ReadFrom.Configuration(context.Configuration)
    .ReadFrom.Services(services)
    .Enrich.FromLogContext());

var app = builder.Build();

app.UseSerilogRequestLogging();

// Skeleton only. Endpoints arrive with the patches that need them:
// agent enrolment in 0014, issuance in 0023.
app.MapGet("/health", () => Results.Ok(new
{
    status = "ok",
    service = "Blinky.Api",
    protocol = Blinky.Contracts.Protocol.SchemaVersion,
}));

app.Run();
