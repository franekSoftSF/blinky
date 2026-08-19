using Blinky.AdcsConnector;
using Serilog;

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddSerilog((services, configuration) => configuration
    .ReadFrom.Configuration(builder.Configuration)
    .ReadFrom.Services(services)
    .Enrich.FromLogContext());

// Optional component. It exists only because ICertRequest3 is DCOM, and DCOM
// does not cross the container boundary. See docs/04-pki-backends.md.
builder.Services.AddWindowsService(options => options.ServiceName = "BlinkyAdcsConnector");
builder.Services.AddHostedService<ConnectorWorker>();

builder.Build().Run();
