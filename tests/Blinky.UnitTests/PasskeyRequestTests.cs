using Blinky.Api.Security;
using Blinky.Contracts;
using Blinky.Domain;
using Blinky.Domain.Entities;

namespace Blinky.UnitTests;

/// <summary>
/// A workstation asks for a passkey and an operator decides (0109).
/// </summary>
/// <remarks>
/// The rule these hold is the one the API's job routes were built on: work is
/// created by an operator and never by an agent. A request is the most an
/// agent can do, and only the console can turn it into a ceremony.
/// </remarks>
public sealed class PasskeyRequestTests
{
    private static readonly DateTime Now = new(2026, 10, 9, 12, 0, 0, DateTimeKind.Utc);

    private static PasskeyRequest Pending() => new()
    {
        TokenSerial = 31234567,
        Cardholder = new Cardholder { DisplayName = "Jan Kowalski", Upn = "jan@ad.example" },
        AgentId = Guid.NewGuid(),
        CreatedAt = Now,
        UpdatedAt = Now,
    };

    [Fact]
    public void Approving_records_the_job_and_who_decided()
    {
        var request = Pending();
        var job = Guid.NewGuid();

        request.Approve(job, "helpdesk1", Now.AddMinutes(5));

        Assert.Equal(PasskeyRequestState.Approved, request.State);
        Assert.Equal(job, request.JobId);
        Assert.Equal("helpdesk1", request.DecidedBy);
        Assert.Equal(Now.AddMinutes(5), request.DecidedAt);
    }

    [Fact]
    public void A_refusal_needs_a_reason_because_the_workstation_shows_it()
    {
        var request = Pending();

        Assert.Throws<ArgumentException>(() => request.Reject(" ", "helpdesk1", Now));
        Assert.Equal(PasskeyRequestState.Pending, request.State);

        request.Reject("not on the passkey pilot", "helpdesk1", Now);

        Assert.Equal(PasskeyRequestState.Rejected, request.State);
        Assert.Equal("not on the passkey pilot", request.RejectionReason);
    }

    [Fact]
    public void A_decided_request_cannot_be_decided_again()
    {
        // Two operators answering at once: the second must not turn a refusal
        // into an approval, or approve a second job for one request.
        var rejected = Pending();
        rejected.Reject("no", "helpdesk1", Now);

        Assert.Throws<InvalidOperationException>(() => rejected.Approve(Guid.NewGuid(), "helpdesk2", Now));

        var approved = Pending();
        approved.Approve(Guid.NewGuid(), "helpdesk1", Now);

        Assert.Throws<InvalidOperationException>(() => approved.Reject("changed my mind", "helpdesk1", Now));
    }

    [Theory]
    [InlineData("/api/passkeys/requests")]
    [InlineData("/api/passkeys/requests/{id:guid}/approve")]
    [InlineData("/api/passkeys/requests/{id:guid}/reject")]
    public void Deciding_belongs_to_the_console(string route) =>
        Assert.Contains(route, AgentAuthenticationMiddleware.OperatorPaths);

    [Fact]
    public void Asking_belongs_to_the_agent()
    {
        // Not an operator path, so the middleware demands the agent's
        // certificate - and with it, which workstation asked.
        Assert.DoesNotContain("/api/tokens/{serial:long}/passkey-request",
            AgentAuthenticationMiddleware.OperatorPaths);
    }

    [Fact]
    public void The_state_crosses_the_pipe_as_the_enum_name()
    {
        // A tray older than a fourth state should show the word, not misread a number.
        Assert.Equal(nameof(PasskeyRequestState.Pending), PasskeyRequestView.Pending);
        Assert.Equal(nameof(PasskeyRequestState.Approved), PasskeyRequestView.Approved);
        Assert.Equal(nameof(PasskeyRequestState.Rejected), PasskeyRequestView.Rejected);
    }
}
