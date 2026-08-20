using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using Blinky.Agent.Service;
using Blinky.Contracts;
using Microsoft.Extensions.Logging.Abstractions;

namespace Blinky.UnitTests;

/// <summary>
/// The channel between session 0 and the user's session, driven from both ends
/// in one process. The window itself needs a person; the protocol does not, and
/// this is the half that can go wrong silently.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class UserPromptTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    [Fact]
    public async Task A_pin_typed_in_the_user_session_reaches_the_service()
    {
        var pipe = UniquePipe();
        var prompts = new UserPrompts(NullLogger<UserPrompts>.Instance,
            TimeSpan.FromSeconds(10), pipe);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(15));

        var asking = prompts.AskForPinAsync(29177301, 3, "signing a certificate request",
            cancellation.Token);

        var request = await AnswerAsync(pipe, PromptResponse.WithPin("123456"),
            cancellation.Token);

        Assert.Equal(PromptRequest.Pin, request.Type);
        Assert.Equal(29177301, request.TokenSerial);
        Assert.Equal(3, request.AttemptsRemaining);
        Assert.Equal("123456", await asking);
    }

    [Fact]
    public async Task Cancelling_yields_no_pin_rather_than_an_empty_one()
    {
        // An empty string would be sent to the card and cost an attempt.
        var pipe = UniquePipe();
        var prompts = new UserPrompts(NullLogger<UserPrompts>.Instance,
            TimeSpan.FromSeconds(10), pipe);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(15));

        var asking = prompts.AskForPinAsync(29177301, null, "signing", cancellation.Token);

        await AnswerAsync(pipe, PromptResponse.Cancel(), cancellation.Token);

        Assert.Null(await asking);
    }

    [Fact]
    public async Task With_nobody_listening_the_prompt_times_out_and_returns_nothing()
    {
        // No fallback to a configured PIN, ever: a PIN in configuration is a
        // PIN on disk.
        var prompts = new UserPrompts(NullLogger<UserPrompts>.Instance,
            TimeSpan.FromMilliseconds(300), UniquePipe());

        Assert.Null(await prompts.AskForPinAsync(29177301, 3, "signing",
            CancellationToken.None));
    }

    [Fact]
    public void The_pipe_has_one_name_and_it_is_not_derived_from_anything()
    {
        // Both ends are compiled against the same constant. A name built from
        // a user or a session would be two names that usually agree.
        Assert.Equal("Blinky.Agent.Prompts", AgentPipe.Name);
    }

    /// <summary>
    /// A pipe name of this test's own. The tests run in parallel, and one name
    /// shared between them is one prompt answered by the wrong test.
    /// </summary>
    private static string UniquePipe() => $"Blinky.Test.{Guid.NewGuid():N}";

    /// <summary>Stands in for the UI: connects, reads one prompt, answers it.</summary>
    private static async Task<PromptRequest> AnswerAsync(string pipeName,
        PromptResponse response, CancellationToken ct)
    {
        await using var pipe = new NamedPipeClientStream(".", pipeName,
            PipeDirection.InOut, PipeOptions.Asynchronous);

        await pipe.ConnectAsync(ct);

        using var reader = new StreamReader(pipe, Encoding.UTF8, false, 1024, leaveOpen: true);
        var line = await reader.ReadLineAsync(ct)
                   ?? throw new InvalidOperationException("The service sent nothing.");

        var request = JsonSerializer.Deserialize<PromptRequest>(line, Json)!;

        var reply = JsonSerializer.Serialize(response, Json) + "\n";
        await pipe.WriteAsync(Encoding.UTF8.GetBytes(reply), ct);
        await pipe.FlushAsync(ct);

        return request;
    }
}
