using System.Security.Cryptography.X509Certificates;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

builder.Host.UseSerilog((context, services, configuration) => configuration
    .ReadFrom.Configuration(context.Configuration)
    .ReadFrom.Services(services)
    .Enrich.FromLogContext());

var app = builder.Build();

app.UseSerilogRequestLogging();

// Skeleton only. Endpoints arrive with the patches that need them:
// agent enrolment in 0014, issuance in 0023.
app.MapGet("/health", () => Results.Ok(new
{
    status = "ok",
    service = "Blinky.Api",
    protocol = Blinky.Contracts.Protocol.SchemaVersion,
}));

// Who is calling, according to the edge. The client certificate is verified by
// nginx and forwarded as a URL-escaped PEM; the API never terminates TLS itself.
//
// These headers are only trustworthy because the API is not published outside
// the compose network and the edge overwrites whatever the client sent. Exposing
// api:8080 directly would make this endpoint a lie.
app.MapGet("/api/agents/whoami", (HttpContext context) =>
{
    var verified = context.Request.Headers["X-Client-Verify"].ToString();
    if (!string.Equals(verified, "SUCCESS", StringComparison.OrdinalIgnoreCase))
    {
        return Results.Json(new { error = "no verified client certificate" }, statusCode: 401);
    }

    var escaped = context.Request.Headers["X-Client-Cert"].ToString();
    if (string.IsNullOrEmpty(escaped))
    {
        return Results.Json(new { error = "certificate not forwarded" }, statusCode: 401);
    }

    X509Certificate2 certificate;
    try
    {
        certificate = X509Certificate2.CreateFromPem(Uri.UnescapeDataString(escaped));
    }
    catch (Exception ex)
    {
        return Results.Json(new { error = "unparseable certificate", detail = ex.Message },
            statusCode: 400);
    }

    return Results.Ok(new
    {
        subject = certificate.Subject,
        issuer = certificate.Issuer,
        thumbprint = certificate.Thumbprint,
        notAfter = certificate.NotAfter,
    });
});

app.Run();
