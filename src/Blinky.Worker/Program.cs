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

builder.Build().Run();
