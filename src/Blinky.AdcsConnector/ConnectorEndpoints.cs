using Blinky.Contracts;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Blinky.AdcsConnector;

/// <summary>
/// The connector's whole surface: four things a CA can be asked, and a
/// liveness answer.
/// </summary>
/// <remarks>
/// Deliberately thin. Everything that decides what a certificate should say
/// lives on the other side of this wire, in <c>AdcsCertificateAuthority</c>,
/// and is shared with the CES transport; anything decided here would be a
/// decision the CES route does not make, which is how "switching transports is
/// one config value" stops being true.
/// </remarks>
public static class ConnectorEndpoints
{
    private const string TemplateAttribute = "CertificateTemplate:";

    public static void MapConnector(this IEndpointRouteBuilder app)
    {
        // No CA call. This answers "is the service up", which is a different
        // question from "is the CA reachable" - describe answers that one, and
        // conflating them makes a healthy connector in front of a stopped CA
        // look like a connector that failed to start.
        app.MapGet("/connector/health", () => Results.Ok(new
        {
            ok = true,
            schema = AdcsTransport.SchemaVersion,
            version = ConnectorVersion.Value,
        }));

        app.MapGet("/connector/describe", async (
            CertificateServiceHost host, string? caConfig, CancellationToken ct) =>
        {
            var description = await host.RunAsync(
                "Describe", (services, token) => services.Describe(caConfig, token), ct);

            return Results.Ok(new AdcsDescribeResponse(
                AdcsTransport.SchemaVersion,
                ConnectorVersion.Value,
                description.CaConfig,
                description.CaName,
                description.AdminAvailable,
                Encode(description.CertificateChain),
                description.Templates));
        });

        app.MapPost("/connector/submit", async (
            AdcsSubmitRequest request, CertificateServiceHost host, ConnectorOptions options,
            CancellationToken ct) =>
        {
            if (Refuse(request.SchemaVersion) is { } mismatch)
            {
                return mismatch;
            }

            if (!TryDecode(request.Request, out var bytes))
            {
                return Problem("The request is not base64.");
            }

            var template = TemplateIn(request.Attributes);

            if (options.AllowedTemplates.Count > 0
                && (template is null
                    || !options.AllowedTemplates.Contains(template, StringComparer.OrdinalIgnoreCase)))
            {
                // Named, because the alternative is an operator watching ADCS
                // deny a template it was never asked about.
                return Problem(
                    "This connector was configured to submit against "
                    + string.Join(", ", options.AllowedTemplates)
                    + " and the request names " + (template ?? "no template") + ".");
            }

            var outcome = await host.RunAsync(
                "Submit",
                (services, token) => services.Submit(
                    bytes, request.Format, request.Attributes, request.CaConfig, token),
                ct);

            return Results.Ok(new AdcsSubmitResponse(
                outcome.Disposition,
                outcome.RequestId,
                Encode(outcome.Certificate),
                Encode(outcome.Chain),
                outcome.StatusMessage,
                outcome.HResult));
        });

        app.MapPost("/connector/retrieve", async (
            AdcsRetrieveRequest request, CertificateServiceHost host, CancellationToken ct) =>
        {
            if (Refuse(request.SchemaVersion) is { } mismatch)
            {
                return mismatch;
            }

            var outcome = await host.RunAsync(
                "Retrieve",
                (services, token) => services.Retrieve(request.RequestId, request.CaConfig, token),
                ct);

            return Results.Ok(new AdcsSubmitResponse(
                outcome.Disposition,
                outcome.RequestId,
                Encode(outcome.Certificate),
                Encode(outcome.Chain),
                outcome.StatusMessage,
                outcome.HResult));
        });

        app.MapPost("/connector/revoke", async (
            AdcsRevokeRequest request, CertificateServiceHost host, CancellationToken ct) =>
        {
            if (Refuse(request.SchemaVersion) is { } mismatch)
            {
                return mismatch;
            }

            if (!IsSerial(request.SerialNumber))
            {
                return Problem("A serial number is hex digits and nothing else.");
            }

            var outcome = await host.RunAsync(
                "Revoke",
                (services, token) => services.Revoke(
                    request.SerialNumber, request.Reason, request.EffectiveAt, request.CaConfig,
                    token),
                ct);

            return Results.Ok(new AdcsRevokeResponse(
                outcome.Revoked, outcome.StatusMessage, outcome.HResult));
        });
    }

    /// <summary>
    /// The template a request names, or null. The attribute string is the CA's
    /// format and is passed through untouched; this only reads it.
    /// </summary>
    public static string? TemplateIn(string? attributes)
    {
        if (attributes is null)
        {
            return null;
        }

        foreach (var line in attributes.Split(['\n', '\r'], StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = line.Trim();

            if (trimmed.StartsWith(TemplateAttribute, StringComparison.OrdinalIgnoreCase))
            {
                var name = trimmed[TemplateAttribute.Length..].Trim();

                return name.Length == 0 ? null : name;
            }
        }

        return null;
    }

    /// <summary>
    /// Hex and nothing else. A serial number reaches <c>ICertAdmin2</c> as a
    /// string and there is no reason for anything else to be in it.
    /// </summary>
    public static bool IsSerial(string? value) =>
        value is { Length: > 0 } && value.All(char.IsAsciiHexDigit);

    private static IResult? Refuse(int schemaVersion) =>
        AdcsTransport.IsSupported(schemaVersion)
            ? null
            : Problem(
                "This connector speaks schema " + AdcsTransport.MinimumSupportedVersion + " to "
                + AdcsTransport.MaximumSupportedVersion + " and was sent " + schemaVersion
                + ". Upgrade the connector on the certification authority.");

    private static IResult Problem(string reason) =>
        Results.BadRequest(new AdcsProblem(reason));

    private static bool TryDecode(string value, out byte[] bytes)
    {
        try
        {
            bytes = Convert.FromBase64String(value.Trim());

            return bytes.Length > 0;
        }
        catch (FormatException)
        {
            bytes = [];

            return false;
        }
    }

    private static string? Encode(byte[]? value) =>
        value is null ? null : Convert.ToBase64String(value);
}
