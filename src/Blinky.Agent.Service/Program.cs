using Microsoft.Extensions.Configuration;
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

// Deployment settings live beside the agent's other state rather than in the
// installation directory, for one reason: this file carries the bootstrap
// token, and %ProgramFiles% grants BUILTIN\\Users read. AgentPaths already
// creates this directory with that inheritance switched off.
if (OperatingSystem.IsWindows())
{
    builder.Configuration.AddJsonFile(
        Path.Combine(AgentPaths.Root, "agent.json"), optional: true, reloadOnChange: false);

    // Last, so it wins. The registry is what the installer writes and what a
    // domain policy can change afterwards without touching a file on every
    // workstation; a JSON file left over from a hand install should not
    // override what the fleet was told.
    ((IConfigurationBuilder)builder.Configuration).Add(new RegistryConfigurationSource());
}

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

// The certificate store is where a client certificate belongs on Windows, and
// is the default. A configured directory is an explicit request for files -
// a bench that does not want to touch certlm, or a platform that has no store.
builder.Services.AddSingleton<IAgentIdentity>(services =>
    options.IdentityDirectory is { Length: > 0 } directory
        ? new FileAgentIdentity(directory)
        : OperatingSystem.IsWindows()
            ? new CertificateStoreIdentity(
                services.GetRequiredService<ILogger<CertificateStoreIdentity>>())
            : FileAgentIdentity.Default());

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
