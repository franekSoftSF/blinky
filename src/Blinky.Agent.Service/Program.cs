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
builder.Services.AddSingleton<JobExecutor>();

// LocalSystem, session 0. It owns the reader and executes jobs; it cannot draw
// a PIN prompt and cannot prove who is at the keyboard - that is Agent.Ui,
// which arrives with the first workflow that needs one.
builder.Services.AddWindowsService(o => o.ServiceName = "BlinkyAgent");
builder.Services.AddHostedService<AgentWorker>();

builder.Build().Run();
