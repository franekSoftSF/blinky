using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Blinky.Contracts;

namespace Blinky.Agent.Ui;

/// <summary>
/// The user session's half of the conversation with the service.
/// </summary>
/// <remarks>
/// Connects, waits for something to show, shows it, answers, and reconnects.
/// One prompt per connection: the service opens a pipe when it needs something
/// and closes it afterwards, so there is no long-lived channel to keep alive or
/// to leak a PIN through.
/// </remarks>
public sealed class PromptClient(Func<PromptRequest, Task<PromptResponse>> show)
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    /// <summary>
    /// Waits for prompts until cancelled. Errors are swallowed and retried: the
    /// service not running is the normal state most of the time, and a UI that
    /// gave up would need restarting by hand.
    /// </summary>
    public async Task RunAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await WaitForOneAsync(ct);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch
            {
                await Task.Delay(TimeSpan.FromSeconds(2), ct);
            }
        }
    }

    private async Task WaitForOneAsync(CancellationToken ct)
    {
        await using var pipe = new NamedPipeClientStream(".", AgentPipe.Name,
            PipeDirection.InOut, PipeOptions.Asynchronous);

        await pipe.ConnectAsync(ct);

        using var reader = new StreamReader(pipe, Encoding.UTF8, false, 1024, leaveOpen: true);

        var line = await reader.ReadLineAsync(ct);
        if (line is null)
        {
            return;
        }

        var request = JsonSerializer.Deserialize<PromptRequest>(line, Json);
        if (request is null)
        {
            return;
        }

        // Dismiss used to stop here, before reaching any window, so a touch
        // prompt stayed on screen after the card had been touched. It goes to
        // the window now, like the job messages of 0084a.
        var response = await show(request);

        // Nothing to send back: the card is what a touch waits on, and the rest
        // are things the window is told rather than asked.
        if (request.Type is PromptRequest.Touch or PromptRequest.Dismiss
            or PromptRequest.JobStarted or PromptRequest.JobStep or PromptRequest.JobEnded)
        {
            return;
        }

        var reply = JsonSerializer.Serialize(response, Json) + "\n";
        await pipe.WriteAsync(Encoding.UTF8.GetBytes(reply), ct);
        await pipe.FlushAsync(ct);
    }
}
