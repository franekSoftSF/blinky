using Blinky.Contracts;

namespace Blinky.UnitTests;

/// <summary>
/// Which side runs a job. Two sides have to agree, and disagreeing is not a
/// visible failure: the job is claimed, held for the length of a lease,
/// returned to the queue by the watchdog, and claimed again. A loop with no
/// error in it and no progress either.
/// </summary>
public sealed class JobTypeTests
{
    [Theory]
    [InlineData(JobType.Inventory)]
    [InlineData(JobType.Enroll)]
    [InlineData(JobType.Renew)]
    [InlineData(JobType.Revoke)]
    [InlineData(JobType.UnblockPin)]
    [InlineData(JobType.RotateMgmtKey)]
    [InlineData(JobType.ResetCard)]
    public void Everything_that_touches_a_card_is_an_agent_s(JobType type)
    {
        Assert.True(JobTypes.IsForAgent(type));
        Assert.False(JobTypes.IsMaintenance(type));
    }

    [Fact]
    public void Publishing_a_revocation_list_needs_no_card_and_so_no_agent()
    {
        Assert.False(JobTypes.IsForAgent(JobType.PublishCrl));
        Assert.True(JobTypes.IsMaintenance(JobType.PublishCrl));
    }

    [Fact]
    public void Every_type_is_one_or_the_other_and_never_both()
    {
        // A type added later and classified nowhere would default to being an
        // agent's, and an agent would take it and sit on it. This is the test
        // that fails when somebody adds one without deciding.
        foreach (var type in Enum.GetValues<JobType>())
        {
            Assert.NotEqual(JobTypes.IsForAgent(type), JobTypes.IsMaintenance(type));
        }
    }
}
