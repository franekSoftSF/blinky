using System;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Blinky.Contracts;

namespace Blinky.Agent.Ui;

/// <summary>
/// Asks the service to do something, and waits for the answer.
/// </summary>
/// <remarks>
/// One connection per request. The service is the only thing on this machine
/// that touches a reader, so everything the tray shows and everything it
/// changes goes through here — the window holds no card handle of its own.
/// </remarks>
public sealed class RequestClient
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    /// <summary>
    /// Short on purpose. The service is either running on this machine or it is
    /// not; a tray that hangs for thirty seconds looks broken in a way that
    /// "the service is not answering" does not.
    /// </summary>
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(3);

    /// <summary>
    /// Long enough for a card operation, because that is what is on the other
    /// end: a reader sweep, or a card being asked to change its PIN.
    /// </summary>
    private static readonly TimeSpan CallTimeout = TimeSpan.FromSeconds(60);

    public async Task<AgentResponse> SendAsync(AgentRequest request, AgentSecrets? secrets = null,
        CancellationToken ct = default)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(CallTimeout);

        try
        {
            await using var pipe = new NamedPipeClientStream(".", AgentRequestPipe.Name,
                PipeDirection.InOut, PipeOptions.Asynchronous);

            using var connecting = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
            connecting.CancelAfter(ConnectTimeout);

            await pipe.ConnectAsync(connecting.Token);

            var line = JsonSerializer.Serialize(
                new AgentRequestEnvelope(request, secrets), Json) + "\n";

            await pipe.WriteAsync(Encoding.UTF8.GetBytes(line), deadline.Token);
            await pipe.FlushAsync(deadline.Token);

            using var reader = new StreamReader(pipe, Encoding.UTF8, false, 4096, leaveOpen: true);

            var answer = await reader.ReadLineAsync(deadline.Token);

            return answer is null
                ? AgentResponse.Failed(Strings.Current["Error.NoService"])
                : JsonSerializer.Deserialize<AgentResponse>(answer, Json)
                  ?? AgentResponse.Failed(Strings.Current["Error.NoService"]);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return AgentResponse.Failed(Strings.Current["Error.NoService"]);
        }
        catch (Exception ex) when (ex is IOException or TimeoutException
                                      or UnauthorizedAccessException)
        {
            return AgentResponse.Failed(Strings.Current["Error.NoService"]);
        }
    }
}
