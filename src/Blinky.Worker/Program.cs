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

    // Which CA this worker has anything to do for. With a Microsoft CA the
    // answer is nothing yet, and that is deliberate rather than unfinished work
    // left switched on: the revocation list is the CA's own, published at its own
    // distribution point, and MaintenanceRunner is built for a CA whose list lives
    // in memory. It replays every revocation into the CA before building the
    // list, which against ADCS would re-revoke every revoked certificate at the
    // CA every cycle and then fail for want of a list to write. Revocation
    // through ADCS is 0034, and it happens when Blinky revokes, not on a timer.
    var caBackend = Blinky.Pki.Adcs.AdcsInstance.Backend(builder.Configuration["Blinky:Ca:Backend"]);

    // The CA, here as well as in the API - but for different halves of the
    // job. The worker builds the revocation list and writes it; the API only
    // serves what is on disk. One producer, so there is one list rather than
    // two processes each holding their own idea of who has been revoked.
    var caDirectory = builder.Configuration["Blinky:Ca:Directory"];

    if (caBackend == Blinky.Domain.CaBackend.BuiltIn
        && !string.IsNullOrWhiteSpace(caDirectory) && Directory.Exists(caDirectory))
    {
        // Recurring work, as jobs rather than as a loop. A loop does the thing
        // and leaves nothing behind: no row in the console, no attempts, no
        // lease, no watchdog, and no record that it ran. The engine already
        // gives all of that to anything that is a job, so this schedules and the
        // runner below executes.
        //
        // Scheduled only where something runs it. It used to be registered
        // whenever there was a database, so a worker with no CA directory wrote
        // a revocation-list job every period that nothing would ever pick up,
        // and each one expired in the console as a failure.
        var crlHours = builder.Configuration.GetValue("Blinky:Ca:CrlRefreshHours", 2);

        builder.Services.AddSingleton(new ScheduleOptions(
            Tick: TimeSpan.FromMinutes(1),
            CrlInterval: TimeSpan.FromHours(crlHours),

            // Shorter than the interval on purpose: a publication still queued
            // when its successor is scheduled is one nobody is going to run.
            CrlDeadline: TimeSpan.FromHours(Math.Max(1, crlHours - 1))));

        builder.Services.AddHostedService<ScheduledJobs>();

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
