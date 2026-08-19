using Blinky.Agent.Service;
using Serilog;

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddSerilog((services, configuration) => configuration
    .ReadFrom.Configuration(builder.Configuration)
    .ReadFrom.Services(services)
    .Enrich.FromLogContext());

// LocalSystem, session 0. It owns the reader and executes jobs; it cannot draw
// a PIN prompt and cannot prove who is at the keyboard - that is Agent.Ui.
builder.Services.AddWindowsService(options => options.ServiceName = "BlinkyAgent");
builder.Services.AddHostedService<AgentWorker>();

builder.Build().Run();
