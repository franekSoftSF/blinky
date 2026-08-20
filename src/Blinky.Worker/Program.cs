using Blinky.Infrastructure;
using Blinky.Worker;
using Serilog;

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddSerilog((services, configuration) => configuration
    .ReadFrom.Configuration(builder.Configuration)
    .ReadFrom.Services(services)
    .Enrich.FromLogContext());

// Single replica by design: the expiry scanner and the job watchdog must not
// run twice. See docs/01-architecture.md.
builder.Services.AddHostedService<LifecycleWorker>();

var host = builder.Build();

// Same check, same policy as the API: report and carry on.
var connectionString = builder.Configuration.GetConnectionString("Blinky");
var logger = host.Services.GetRequiredService<ILogger<Program>>();

if (string.IsNullOrWhiteSpace(connectionString))
{
    logger.LogError("Schema validation skipped: no connection string configured");
}
else
{
    var schema = SchemaValidator.Validate(
        BlinkySessionFactory.BuildConfiguration(connectionString));

    if (schema.IsValid)
    {
        logger.LogInformation("Schema validation: {Summary}", schema.Summary);
    }
    else
    {
        logger.LogError("Schema validation FAILED: {Summary}", schema.Summary);
    }
}

host.Run();

/// <summary>Named so the worker has a logger category of its own.</summary>
public partial class Program;
