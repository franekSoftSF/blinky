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
    public async Task A_fido2_pin_prompt_says_how_long_the_pin_may_be()
    {
        // The window used to assume PIV's six to eight and refused the ninth
        // character of a FIDO2 PIN, which CTAP allows up to 63.
        var pipe = UniquePipe();
        var prompts = new UserPrompts(NullLogger<UserPrompts>.Instance,
            TimeSpan.FromSeconds(10), pipe);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(15));

        var asking = prompts.AskForPinAsync(29177301, 8, "creating a passkey",
            cancellation.Token, "Security key PIN (FIDO2)", 4, 63, PromptRequest.Fido2);

        var request = await AnswerAsync(pipe, PromptResponse.WithPin("a-long-fido2-pin"),
            cancellation.Token);

        Assert.Equal(4, request.MinLength);
        Assert.Equal(63, request.MaxLength);

        // Said, so the window does not offer to "unlock" anything.
        Assert.Equal(PromptRequest.Fido2, request.Applet);
        Assert.Equal("a-long-fido2-pin", await asking);
    }

    [Fact]
    public void A_prompt_from_before_the_length_fields_reads_as_a_piv_pin()
    {
        // Additive, so no version bump: what an older service sends has no
        // lengths, and the window falls back to six to eight.
        var request = JsonSerializer.Deserialize<PromptRequest>(
            """{"type":"Pin","title":"Blinky needs your PIN","message":"signing","tokenSerial":1}""",
            Json)!;

        Assert.Null(request.MinLength);
        Assert.Null(request.MaxLength);
        Assert.Null(request.Applet);
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
    [Fact]
    public async Task A_provisional_pin_waits_longer_than_an_ordinary_prompt()
    {
        // The PIN is on the key by the time it is shown. Giving up at the
        // ordinary timeout would leave a key with a PIN nobody kept and no
        // passkey; the notice waits as long as it is told to instead.
        var pipe = UniquePipe();
        var prompts = new UserPrompts(NullLogger<UserPrompts>.Instance,
            TimeSpan.FromMilliseconds(500), pipe);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(15));

        var showing = prompts.ShowNoticeAsync(29177301, "Write down this FIDO2 PIN", "1234-5678",
            cancellation.Token, PromptRequest.Fido2, TimeSpan.FromSeconds(10));

        await using var client = new NamedPipeClientStream(".", pipe, PipeDirection.InOut, PipeOptions.Asynchronous);
        await client.ConnectAsync(cancellation.Token);

        using var reader = new StreamReader(client, Encoding.UTF8, false, 1024, leaveOpen: true);
        var request = JsonSerializer.Deserialize<PromptRequest>(
            (await reader.ReadLineAsync(cancellation.Token))!, Json)!;

        // Three times the ordinary timeout, as somebody finding a pen.
        await Task.Delay(TimeSpan.FromMilliseconds(1500), cancellation.Token);

        await client.WriteAsync(Encoding.UTF8.GetBytes(
            JsonSerializer.Serialize(PromptResponse.Cancel(), Json) + "\n"), cancellation.Token);
        await client.FlushAsync(cancellation.Token);

        await showing;

        Assert.Equal(PromptRequest.Notice, request.Type);
        Assert.Equal(PromptRequest.Fido2, request.Applet);
    }

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
