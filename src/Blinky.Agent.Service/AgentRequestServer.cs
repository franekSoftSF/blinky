using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Blinky.Contracts;

namespace Blinky.Agent.Service;

/// <summary>
/// Listens for what the person at the keyboard asked for.
/// </summary>
/// <remarks>
/// <para>
/// The mirror of <see cref="UserPrompts"/>, and the direction matters. That one
/// carries answers: the service decides a person is needed and waits for a
/// reply. This one carries requests: somebody clicked, and the service acts.
/// </para>
/// <para>
/// The access control is identical — <c>INTERACTIVE</c> and
/// <c>LocalSystem</c>, never <c>Everyone</c> — but it is now carrying more
/// weight. It stopped guarding "who may answer a prompt" and started guarding
/// "who may begin an operation on the token in this machine". That is a
/// defensible boundary, since a PIN prompt already assumes physical presence
/// plus a session, but it should be held deliberately. See docs/10-agent-ui.md.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class AgentRequestServer(
    CardOperations cards,
    PukUnblock unblock,
    AgentOptions options,
    ILogger<AgentRequestServer> logger) : BackgroundService
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("Listening for user requests on {Pipe}", AgentRequestPipe.Name);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ServeOneAsync(stoppingToken);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception ex)
            {
                // One bad connection must not take the listener down: the tray
                // would then be dead until somebody restarted a service they
                // cannot see.
                logger.LogWarning("A request could not be served: {Message}", ex.Message);

                await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken);
            }
        }
    }

    private async Task ServeOneAsync(CancellationToken ct)
    {
        await using var pipe = Listen();
        await pipe.WaitForConnectionAsync(ct);

        using var reader = new StreamReader(pipe, Encoding.UTF8, false, 4096, leaveOpen: true);

        var line = await reader.ReadLineAsync(ct);
        if (line is null)
        {
            return;
        }

        var envelope = JsonSerializer.Deserialize<AgentRequestEnvelope>(line, Json);

        var response = envelope is null
            ? AgentResponse.Failed("The request could not be read.")
            : await HandleAsync(envelope, ct);

        var reply = JsonSerializer.Serialize(response, Json) + "\n";
        await pipe.WriteAsync(Encoding.UTF8.GetBytes(reply), ct);
        await pipe.FlushAsync(ct);
    }

    /// <remarks>
    /// The request is logged and the secrets are not. They travel in a separate
    /// record for exactly this reason — so that logging the one cannot reach
    /// the other by accident.
    /// </remarks>
    private async Task<AgentResponse> HandleAsync(AgentRequestEnvelope envelope,
        CancellationToken ct)
    {
        var request = envelope.Request;

        logger.LogInformation("User request: {Op}{Token}", request.Op,
            request.TokenSerial is { } serial ? $" for token {serial}" : string.Empty);

        try
        {
            return request.Op switch
            {
                AgentRequest.ListTokens =>
                    new AgentResponse(true, Tokens: await cards.ListTokensAsync(ct)),

                AgentRequest.GetPinPolicy =>
                    new AgentResponse(true, PinComplexityPolicy: options.PinPolicy),

                AgentRequest.ChangePin when request.TokenSerial is { } token =>
                    cards.ChangePin(token, envelope.Secrets?.CurrentPin,
                        envelope.Secrets?.NewPin, options.PinPolicy),

                AgentRequest.UnblockPin when request.TokenSerial is { } token =>
                    await unblock.UnblockAsync(token, envelope.Secrets?.NewPin ?? string.Empty,
                        options.PinPolicy, ct),

                AgentRequest.ChangePin or AgentRequest.UnblockPin =>
                    AgentResponse.Failed("That request has to name a token."),

                _ => AgentResponse.Failed($"This agent does not know the request {request.Op}."),
            };
        }
        catch (Exception ex)
        {
            logger.LogWarning("Request {Op} failed: {Message}", request.Op, ex.Message);

            return AgentResponse.Failed(ex.Message);
        }
    }

    private static NamedPipeServerStream Listen()
    {
        var security = new PipeSecurity();

        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.InteractiveSid, null),
            PipeAccessRights.ReadWrite, AccessControlType.Allow));

        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl, AccessControlType.Allow));

        return NamedPipeServerStreamAcl.Create(AgentRequestPipe.Name, PipeDirection.InOut,
            maxNumberOfServerInstances: 4, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous, inBufferSize: 0, outBufferSize: 0, security);
    }
}
