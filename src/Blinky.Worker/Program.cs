using Blinky.Infrastructure;
using Blinky.Worker;
using NHibernate;
using Serilog;

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddSerilog((services, configuration) => configuration
    .ReadFrom.Configuration(builder.Configuration)
    .ReadFrom.Services(services)
    .Enrich.FromLogContext());

// Single replica by design: the expiry scanner and the job watchdog must not
// run twice. See docs/01-architecture.md.
builder.Services.AddHostedService<LifecycleWorker>();

var connection = builder.Configuration.GetConnectionString("Blinky");
if (!string.IsNullOrWhiteSpace(connection))
{
    builder.Services.AddSingleton<ISessionFactory>(
        _ => BlinkySessionFactory.Build(connection));

    builder.Services.AddHostedService(services => new JobWatchdog(
        services.GetRequiredService<ISessionFactory>(),
        services.GetRequiredService<ILogger<JobWatchdog>>(),
        TimeSpan.FromSeconds(
            builder.Configuration.GetValue("Blinky:Watchdog:IntervalSeconds", 30))));

    // Recurring work, as jobs rather than as a loop. A loop does the thing and
    // leaves nothing behind: no row in the console, no attempts, no lease, no
    // watchdog, and no record that it ran. The engine already gives all of
    // that to anything that is a job, so this schedules and the runner below
    // executes.
    var crlHours = builder.Configuration.GetValue("Blinky:Ca:CrlRefreshHours", 2);

    builder.Services.AddSingleton(new ScheduleOptions(
        Tick: TimeSpan.FromMinutes(1),
        CrlInterval: TimeSpan.FromHours(crlHours),

        // Shorter than the interval on purpose: a publication still queued
        // when its successor is scheduled is one nobody is going to run.
        CrlDeadline: TimeSpan.FromHours(Math.Max(1, crlHours - 1))));

    builder.Services.AddHostedService<ScheduledJobs>();

    // The CA, here as well as in the API - but for different halves of the
    // job. The worker builds the revocation list and writes it; the API only
    // serves what is on disk. One producer, so there is one list rather than
    // two processes each holding their own idea of who has been revoked.
    var caDirectory = builder.Configuration["Blinky:Ca:Directory"];

    if (!string.IsNullOrWhiteSpace(caDirectory) && Directory.Exists(caDirectory))
    {
        builder.Services.AddSingleton<Blinky.Pki.ICertificateAuthority>(_ =>
            Blinky.Pki.BuiltIn.BuiltInCaFactory.LoadFromDirectory(
                caDirectory,
                builder.Configuration["Blinky:Ca:Password"],
                builder.Configuration.GetValue("Blinky:Ca:AllowFileKeys", false),
                TimeSpan.FromHours(
                    builder.Configuration.GetValue("Blinky:Ca:CrlValidityHours", 8))));

        builder.Services.AddSingleton(new MaintenanceOptions(
            Poll: TimeSpan.FromSeconds(20),
            File: builder.Configuration["Blinky:Ca:CrlFile"]
                  ?? "/var/lib/blinky/pki/issuing.crl"));

        builder.Services.AddHostedService<MaintenanceRunner>();
    }
}

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
