using System.Runtime.Versioning;
using Blinky.Agent.Service;
using Serilog;

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddSerilog((services, configuration) => configuration
    .ReadFrom.Configuration(builder.Configuration)
    .ReadFrom.Services(services)
    .Enrich.FromLogContext());

var options = new AgentOptions();
builder.Configuration.GetSection("Agent").Bind(options);
builder.Services.AddSingleton(options);

builder.Services.AddSingleton(options.IdentityDirectory is { Length: > 0 } directory
    ? new AgentIdentity(directory)
    : AgentIdentity.Default());

builder.Services.AddSingleton<InventoryCollector>();
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
}
