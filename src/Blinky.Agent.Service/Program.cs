using System.Runtime.Versioning;
using Blinky.Agent.Service;
using Serilog;

// Before anything opens a file in it. Serilog creates a missing log directory
// itself, with whatever %ProgramData% hands down - which is Users:(RX), in a
// directory that also holds the agent's private key. See AgentPaths.
if (OperatingSystem.IsWindows())
{
    AgentPaths.Secure(AgentPaths.Root);
    AgentPaths.Secure(AgentPaths.Logs);
}

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddSerilog((services, configuration) =>
{
    configuration
        .ReadFrom.Configuration(builder.Configuration)
        .ReadFrom.Services(services)
        .Enrich.FromLogContext();

    // The path is set here rather than in appsettings.json because a
    // configured "%PROGRAMDATA%/..." is taken literally: the sink writes to a
    // directory named after the variable, or to nothing, and the first symptom
    // is a service that looks healthy and logs nowhere. Built from
    // AgentPaths so there is one answer to where the log lives.
    if (OperatingSystem.IsWindows())
    {
        configuration.WriteTo.File(
            Path.Combine(AgentPaths.Logs, "agent-.log"),
            rollingInterval: Serilog.RollingInterval.Day,
            retainedFileCountLimit: 14,
            fileSizeLimitBytes: 32L * 1024 * 1024,
            rollOnFileSizeLimit: true,
            outputTemplate:
            "{Timestamp:yyyy-MM-dd HH:mm:ss.fff} [{Level:u3}] {Message:lj}{NewLine}{Exception}");
    }
});

var options = new AgentOptions();
builder.Configuration.GetSection("Agent").Bind(options);
builder.Services.AddSingleton(options);

builder.Services.AddSingleton(options.IdentityDirectory is { Length: > 0 } directory
    ? new AgentIdentity(directory)
    : AgentIdentity.Default());

builder.Services.AddSingleton<InventoryCollector>();

// One card operation at a time in this process: a poll, a job and a person
// clicking in the tray all end at the same exclusive reader handle.
builder.Services.AddSingleton<CardGate>();

// One client, shared: the worker authenticates it once with the agent's
// certificate and the tray's request handler asks the same backend with the
// same identity. Two clients would mean two identities to keep in step.
builder.Services.AddSingleton(services => new BackendClient(
    options.BackendUrl,
    options.ServerCertificateAuthorityPath,
    options.AcceptAnyServerCertificate));
// Prompts and enrolment both need Windows: one draws in a user session, the
// other holds a reader. Registered only where they can work, and the executor
// refuses the step rather than pretending otherwise.
if (OperatingSystem.IsWindows())
{
    AddWindowsOnlyServices(builder.Services);
}

builder.Services.AddSingleton(services => new JobExecutor(
    services.GetRequiredService<InventoryCollector>(),
    services.GetService<ICardEnrolment>(),
    services.GetRequiredService<ILogger<JobExecutor>>()));

// LocalSystem, session 0. It owns the reader and executes jobs; it cannot draw
// a PIN prompt and cannot prove who is at the keyboard - that is Agent.Ui,
// which arrives with the first workflow that needs one.
builder.Services.AddWindowsService(o => o.ServiceName = "BlinkyAgent");
builder.Services.AddHostedService<AgentWorker>();

builder.Build().Run();

[SupportedOSPlatform("windows")]
static void AddWindowsOnlyServices(IServiceCollection services)
{
    services.AddSingleton<UserPrompts>();
    services.AddSingleton<ICardEnrolment, CardEnrolment>();
    services.AddSingleton<CardOperations>();
    services.AddSingleton<PukUnblock>();

    // The tray's half of the conversation. Windows-only for the same reason
    // everything else here is: it ends at a reader.
    services.AddHostedService<AgentRequestServer>();
}
