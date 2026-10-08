using System.Text.RegularExpressions;
using Blinky.Domain.Entities;

namespace Blinky.UnitTests;

/// <summary>
/// What a machine presents to join, and the limits that make it safe to hand
/// out.
/// </summary>
/// <remarks>
/// Until 0102 this was <c>Blinky:Enrolment:BootstrapToken</c>: one string in
/// <c>docker-compose.yml</c>, the same for every machine and for the life of
/// the deployment, valid wherever it had been pasted and withdrawable only by
/// editing the file and restarting the API. The rules below are what replaced
/// it, and they are asserted rather than reviewed because every one of them is
/// a way the old arrangement failed.
/// </remarks>
public class EnrolmentTokenTests
{
    private static readonly DateTime Now = new(2026, 10, 8, 12, 0, 0, DateTimeKind.Utc);

    private static EnrolmentToken Token(
        EnrolmentPurpose purpose = EnrolmentPurpose.Agent,
        DateTime? expires = null,
        int? maxUses = null,
        int uses = 0,
        string? domain = null) =>
        new()
        {
            Name = "a token",
            Purpose = purpose,
            TokenHash = EnrolmentToken.Fingerprint("whatever"),
            ExpiresAt = expires,
            MaxUses = maxUses,
            Uses = uses,
            AllowedDomain = domain,
            CreatedBy = "superadmin",
            CreatedAt = Now.AddDays(-1),
        };

    [Fact]
    public void A_fresh_token_may_be_spent()
    {
        var token = Token(expires: Now.AddDays(1), maxUses: 5);

        Assert.True(token.IsUsable(Now));
        Assert.Null(token.Spent(Now));
        Assert.Null(token.Refusal(EnrolmentPurpose.Agent, "blinky.lab", Now));
    }

    [Fact]
    public void A_token_past_its_term_is_refused()
    {
        var token = Token(expires: Now.AddSeconds(-1));

        Assert.False(token.IsUsable(Now));
        Assert.Equal("expired", token.Spent(Now));
    }

    /// <summary>
    /// The count is what stops one leaked token enrolling a fleet.
    /// </summary>
    [Fact]
    public void A_token_that_has_been_spent_its_number_of_times_is_refused()
    {
        var token = Token(maxUses: 2, uses: 1);

        Assert.True(token.IsUsable(Now));

        token.Uses++;

        Assert.False(token.IsUsable(Now));
        Assert.Equal("used up", token.Spent(Now));
    }

    [Fact]
    public void A_withdrawn_token_is_refused_even_though_it_has_not_expired()
    {
        var token = Token(expires: Now.AddYears(1), maxUses: 100);
        token.RevokedAt = Now.AddMinutes(-1);

        Assert.False(token.IsUsable(Now));
        Assert.Equal("revoked", token.Spent(Now));
    }

    [Fact]
    public void A_token_with_no_term_and_no_count_is_allowed_but_has_to_be_asked_for()
    {
        // Both limits absent is the old arrangement, one token at a time. It
        // stays possible because a rollout needs it; what changed is that it
        // is a choice somebody makes and a row somebody can see.
        var token = Token();

        Assert.True(token.IsUsable(Now.AddYears(5)));
    }

    /// <summary>
    /// A connector's certificate buys the enrolment agent's signature. A token
    /// handed to a rollout script must not be able to mint one.
    /// </summary>
    [Fact]
    public void An_agent_token_cannot_enrol_a_connector_and_the_other_way_round()
    {
        var agent = Token();
        var connector = Token(EnrolmentPurpose.AdcsConnector);

        Assert.Null(agent.Refusal(EnrolmentPurpose.Agent, null, Now));
        Assert.NotNull(agent.Refusal(EnrolmentPurpose.AdcsConnector, null, Now));

        Assert.Null(connector.Refusal(EnrolmentPurpose.AdcsConnector, null, Now));
        Assert.NotNull(connector.Refusal(EnrolmentPurpose.Agent, null, Now));
    }

    [Theory]
    [InlineData("blinky.lab", true)]
    [InlineData("BLINKY.LAB", true)]
    [InlineData("somewhere.else", false)]
    [InlineData(null, false)]
    public void A_token_tied_to_a_domain_only_works_from_it(string? reported, bool admitted)
    {
        var token = Token(domain: "blinky.lab");

        Assert.Equal(admitted, token.Refusal(EnrolmentPurpose.Agent, reported, Now) is null);
    }

    [Fact]
    public void Two_tokens_are_never_the_same_and_the_row_holds_only_a_hash()
    {
        var (first, firstHash) = EnrolmentToken.Generate();
        var (second, secondHash) = EnrolmentToken.Generate();

        Assert.NotEqual(first, second);
        Assert.NotEqual(firstHash, secondHash);

        Assert.Matches("^[0-9a-f]{64}$", firstHash);
        Assert.Equal(firstHash, EnrolmentToken.Fingerprint(first));

        // URL-safe, because it is pasted into GPOs, command lines and MSI
        // properties, and a '+' or a '/' there is somebody's lost afternoon.
        Assert.Matches("^[A-Za-z0-9_-]+$", first);
        Assert.DoesNotContain(first, firstHash, StringComparison.Ordinal);
    }

    /// <summary>
    /// The deployment files hold no enrolment secret any more.
    /// </summary>
    /// <remarks>
    /// Checked in the source because the failure is silent: somebody adding a
    /// default back "so the lab works" would get a stack that enrols anything
    /// holding a string anybody can read in the repository.
    /// </remarks>
    [Fact]
    public void No_enrolment_token_lives_in_the_deployment_files()
    {
        var compose = Source("docker-compose.yml");

        Assert.DoesNotContain("BootstrapToken", compose, StringComparison.Ordinal);
        Assert.DoesNotContain("ClientFingerprints", compose, StringComparison.Ordinal);

        var example = Source(".env.example");

        Assert.False(
            Regex.IsMatch(example, @"^\s*BOOTSTRAP_TOKEN=", RegexOptions.Multiline),
            ".env.example is handing out an enrolment token again");
    }

    private static string Source(params string[] parts)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null)
        {
            var candidate = Path.Combine([directory.FullName, .. parts]);

            if (File.Exists(candidate))
            {
                return File.ReadAllText(candidate);
            }

            directory = directory.Parent;
        }

        throw new FileNotFoundException($"Could not find {Path.Combine(parts)} above {AppContext.BaseDirectory}");
    }
}
