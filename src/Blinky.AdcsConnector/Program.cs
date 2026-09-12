using System.Security.Cryptography.X509Certificates;
using Blinky.AdcsConnector;
using Blinky.Contracts;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Serilog;

// Before anything opens a file in it, for the reason AgentPaths gives: a
// directory created under %ProgramData% inherits BUILTIN\Users:(RX), and this
// one holds the connector's log of who asked it to enrol whom.
ConnectorPaths.Secure(ConnectorPaths.Root);
ConnectorPaths.Secure(ConnectorPaths.Logs);

var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args,

    // A Windows service starts with its working directory in system32, so a
    // content root taken from the current directory finds no appsettings.json
    // and the service comes up with defaults and no explanation.
    ContentRootPath = AppContext.BaseDirectory,
});

// Deployment settings beside the connector's other state rather than in the
// installation directory: this file names the CA and the callers allowed to
// reach it, and %ProgramFiles% grants BUILTIN\Users read.
builder.Configuration.AddJsonFile(
    Path.Combine(ConnectorPaths.Root, "connector.json"), optional: true, reloadOnChange: false);

builder.Host.UseSerilog((context, services, configuration) =>
{
    configuration
        .ReadFrom.Configuration(context.Configuration)
        .ReadFrom.Services(services)
        .Enrich.FromLogContext();

    // Built from ConnectorPaths rather than configured, because a configured
    // "%PROGRAMDATA%/..." is taken literally and the first symptom is a
    // service that looks healthy and logs nowhere.
    configuration.WriteTo.File(
        Path.Combine(ConnectorPaths.Logs, "connector-.log"),
        rollingInterval: RollingInterval.Day,
        retainedFileCountLimit: 30,
        fileSizeLimitBytes: 32L * 1024 * 1024,
        rollOnFileSizeLimit: true,
        outputTemplate:
        "{Timestamp:yyyy-MM-dd HH:mm:ss.fff} [{Level:u3}] {Message:lj}{NewLine}{Exception}");
});

var options = new ConnectorOptions();
builder.Configuration.GetSection("Connector").Bind(options);
builder.Services.AddSingleton(options);

var gate = new ClientCertificateGate(options.AllowedClientThumbprints);

// Refused at startup, not at the first request. An empty allowlist would leave
// a DCOM bridge to a Microsoft CA listening on a network port for anybody who
// asks, and a service that starts in that state will be found in it.
if (gate.IsEmpty)
{
    throw new InvalidOperationException(
        "Connector:AllowedClientThumbprints is empty. The connector will not start without at "
        + "least one client certificate fingerprint, because it would otherwise accept "
        + "enrolment requests from anybody who can reach the port.");
}

builder.Services.AddSingleton(gate);
builder.Services.AddSingleton<ICertificateServices, CertificateServices>();
builder.Services.AddSingleton<CertificateServiceHost>();
builder.Services.AddSingleton<ITemplateDirectory, ActiveDirectoryTemplates>();

// Loaded now, so an enrolment agent that is configured and unusable - expired,
// missing the Certificate Request Agent policy, or with a key this account
// cannot reach - stops the service here, in front of whoever installed it,
// rather than at somebody's enrolment.
builder.Services.AddSingleton(new ConnectorEnrolmentAgent(
    EnrolmentAgentSigner.Load(options.EnrolmentAgent, DateTimeOffset.UtcNow)));

var serverCertificate = ServerCertificate.Load(options.ServerCertificate);

builder.WebHost.UseUrls(options.ListenUrl);
builder.WebHost.ConfigureKestrel(kestrel =>
{
    kestrel.AddServerHeader = false;

    // A CMC carrying a PKCS#10 and an enrolment agent's signature is a few
    // kilobytes. A megabyte is generous and still small enough that nothing
    // reaches the CA by accident.
    kestrel.Limits.MaxRequestBodySize = 1024 * 1024;

    kestrel.ConfigureHttpsDefaults(https =>
    {
        https.ServerCertificate = serverCertificate;
        https.ClientCertificateMode = ClientCertificateMode.RequireCertificate;

        // Accepted at the handshake and decided in the application, so that a
        // refusal is a logged 403 with a reason rather than a TLS alert that
        // tells whoever is diagnosing it nothing. The authorisation is the
        // fingerprint allowlist, which is stricter than chain validation
        // rather than a relaxation of it - see ClientCertificateGate.
        https.ClientCertificateValidation = (_, _, _) => true;
    });
});

builder.Services.AddWindowsService(service => service.ServiceName = "BlinkyAdcsConnector");

var app = builder.Build();

app.Logger.LogInformation(
    "ADCS connector {Version} listening on {Url}, {Count} client certificate(s) allowed, "
    + "schema {Schema}",
    ConnectorVersion.Value, options.ListenUrl, gate.Count, AdcsTransport.SchemaVersion);

app.Use(async (context, next) =>
{
    var certificate = await context.Connection.GetClientCertificateAsync(context.RequestAborted);

    if (!gate.Allows(certificate, TimeProvider.System, out var reason))
    {
        // The fingerprint of what was presented, so that adding a rotated
        // certificate to the allowlist does not require guessing which one
        // was refused. It is a public value.
        app.Logger.LogWarning(
            "{Remote} was refused: {Reason} ({Fingerprint})",
            context.Connection.RemoteIpAddress,
            reason,
            certificate is null ? "none" : ClientCertificateGate.FingerprintOf(certificate));

        context.Response.StatusCode = StatusCodes.Status403Forbidden;

        await context.Response.WriteAsJsonAsync(new AdcsProblem(reason), context.RequestAborted);

        return;
    }

    await next();
});

app.Use(async (context, next) =>
{
    try
    {
        await next();
    }
    catch (CertificateServiceException ex)
    {
        // The CA's own words, passed on. "The request subject name is invalid
        // or too long" is worth more to whoever reads the failure than
        // anything this code could write instead.
        app.Logger.LogError(ex, "The certification authority could not be used");

        context.Response.StatusCode = StatusCodes.Status502BadGateway;

        await context.Response.WriteAsJsonAsync(
            new AdcsProblem(ex.Message, ex.CaHResult is { } code ? "0x" + code.ToString("x8") : null),
            context.RequestAborted);
    }
    catch (BadHttpRequestException ex)
    {
        // A body the model binder could not read. Answered in the contract's
        // own shape rather than with the framework's, so a caller has one
        // failure format to parse and not two.
        context.Response.StatusCode = StatusCodes.Status400BadRequest;

        await context.Response.WriteAsJsonAsync(
            new AdcsProblem("The request body could not be read.", ex.Message),
            context.RequestAborted);
    }
});

app.MapConnector();

app.Run();

/// <summary>The connector's own TLS certificate, from a store or a file.</summary>
internal static class ServerCertificate
{
    public static X509Certificate2 Load(ServerCertificateOptions options)
    {
        if (options.Path is { Length: > 0 } path)
        {
            var fromFile = X509CertificateLoader.LoadPkcs12FromFile(path, options.Password);

            return Require(fromFile, path);
        }

        if (options.Thumbprint is not { Length: > 0 } thumbprint)
        {
            throw new InvalidOperationException(
                "Connector:ServerCertificate needs either a Thumbprint in the machine's personal "
                + "store or a Path to a PKCS#12 file.");
        }

        var wanted = ClientCertificateGate.Normalise(thumbprint);

        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly);

        // Matched against both fingerprints rather than X509FindType, which is
        // SHA-1 only. A thumbprint reaches configuration by being copied out of
        // certutil or the certificate dialog, and which hash those printed
        // depends on the Windows version.
        foreach (var candidate in store.Certificates)
        {
            if (ClientCertificateGate.Normalise(candidate.Thumbprint) == wanted
                || ClientCertificateGate.FingerprintOf(candidate) == wanted)
            {
                return Require(candidate, thumbprint);
            }
        }

        throw new InvalidOperationException(
            "No certificate with fingerprint " + wanted
            + " is in LocalMachine\\My on this machine.");
    }

    private static X509Certificate2 Require(X509Certificate2 certificate, string where)
    {
        if (!certificate.HasPrivateKey)
        {
            throw new InvalidOperationException(
                "The certificate at " + where + " has no private key the service account can "
                + "reach. Grant that account read access to the key - this is the most common "
                + "reason a first start fails.");
        }

        return certificate;
    }
}
