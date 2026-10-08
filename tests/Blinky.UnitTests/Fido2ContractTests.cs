using System.Reflection;
using System.Text.Json;
using Blinky.Agent.Service;
using Blinky.Contracts;

namespace Blinky.UnitTests;

/// <summary>
/// 0074: the four FIDO2 messages, and the version bump that keeps an older agent
/// from misreading them.
/// </summary>
public sealed class Fido2ContractTests
{
    /// <summary>What every agent shipped before 0074 accepted at most.</summary>
    private const int MaximumBeforeFido2 = 1;

    private static readonly Fido2Provisioning Provisioning = new(
        "entra", "Jan Kowalski", new Fido2PinPolicy(Fido2PinMode.ProvisionalRandom, 6, true), "YubiKey", true);

    [Fact]
    public void A_fido2_job_carries_a_version_no_older_agent_accepts()
    {
        var job = JobEnvelope.ProvisionFido2(Guid.NewGuid(), "fido2:x", DateTimeOffset.UtcNow.AddHours(1), null,
            Provisioning);

        Assert.Equal(Protocol.Fido2SchemaVersion, job.SchemaVersion);
        Assert.True(job.SchemaVersion > MaximumBeforeFido2);
        Assert.True(Protocol.IsSupported(job.SchemaVersion));
    }

    [Theory]
    [InlineData(JobType.Inventory)]
    [InlineData(JobType.Enroll)]
    [InlineData(JobType.Revoke)]
    [InlineData(JobType.PublishCrl)]
    public void Every_other_job_stays_at_a_version_deployed_agents_still_read(JobType type)
    {
        // The bump is for one job type. Stamping 2 on everything would have
        // stopped every deployed agent's inventory on the day the API upgraded.
        Assert.Equal(MaximumBeforeFido2, Protocol.VersionFor(type));
        Assert.Equal(MaximumBeforeFido2,
            JobEnvelope.Inventory(Guid.NewGuid(), "i", DateTimeOffset.UtcNow).SchemaVersion);
    }

    [Fact]
    public void Existing_job_types_keep_their_numbers()
    {
        // The envelope carries the type as a number. An older agent survives a
        // type it has never heard of only because it reads 8 as 8 and then
        // refuses on the version; renumbering would make it read a FIDO2 job as
        // something it does know.
        Assert.Equal(
            [0, 1, 2, 3, 4, 5, 6, 7, 8],
            Enum.GetValues<JobType>().Select(t => (int)t));
        Assert.Equal(8, (int)JobType.ProvisionFido2Credential);

        var json = JsonSerializer.Serialize(
            JobEnvelope.ProvisionFido2(Guid.NewGuid(), "k", DateTimeOffset.UtcNow, null, Provisioning),
            new JsonSerializerOptions(JsonSerializerDefaults.Web));
        Assert.Contains("\"type\":8", json);
    }

    [Fact]
    public void This_agent_knows_the_step_it_is_sent()
    {
        // Since the ceremony landed. Before it, the same envelope was refused by
        // name as UnsupportedOperation - which is what an agent from between 0074
        // and this one still does.
        Assert.Contains(Fido2Provisioning.Op, JobExecutor.Supported);
    }

    [Fact]
    public void The_prepare_step_reads_back_as_it_was_written()
    {
        var step = Provisioning.ToStep();

        Assert.Equal(Provisioning, Fido2Provisioning.FromStep(step));
        Assert.Equal(Fido2Provisioning.Op, step.Op);
    }

    [Theory]
    [InlineData("pinMode", "ProvisionalRandomish")]
    [InlineData("pinMode", "7")]
    [InlineData("minPinLength", "3")]
    [InlineData("minPinLength", "64")]
    [InlineData("minPinLength", "six")]
    public void A_policy_this_agent_does_not_understand_is_refused_not_defaulted(string name, string value)
    {
        var arguments = new Dictionary<string, string>(Provisioning.ToStep().Arguments!) { [name] = value };

        Assert.Throws<FormatException>(() =>
            Fido2Provisioning.FromStep(new JobStep(Fido2Provisioning.Op, arguments)));
    }

    [Fact]
    public void The_same_challenge_is_the_same_ceremony()
    {
        var job = Guid.NewGuid();

        Assert.Equal(Fido2CeremonyRequest.IdFor(job, "cdsZ1V10E0BGE4GcG3IK"),
            Fido2CeremonyRequest.IdFor(job, "cdsZ1V10E0BGE4GcG3IK"));
        Assert.NotEqual(Fido2CeremonyRequest.IdFor(job, "cdsZ1V10E0BGE4GcG3IK"),
            Fido2CeremonyRequest.IdFor(job, "cdsZ1V10E0BGE4GcG3IL"));
        Assert.NotEqual(Fido2CeremonyRequest.IdFor(job, "cdsZ1V10E0BGE4GcG3IK"),
            Fido2CeremonyRequest.IdFor(Guid.NewGuid(), "cdsZ1V10E0BGE4GcG3IK"));
    }

    [Fact]
    public void No_fido2_message_has_anywhere_to_put_a_pin()
    {
        // "Shown once, stored nowhere" kept by construction: a PIN that is not a
        // field cannot be serialised, logged, or written into jobs.result.
        Type[] messages =
        [
            typeof(Fido2Provisioning), typeof(Fido2PinPolicy), typeof(Fido2Ready),
            typeof(Fido2CeremonyRequest), typeof(Fido2CeremonyResult), typeof(Fido2Registered),
        ];

        var offenders = messages
            .SelectMany(t => t.GetProperties(BindingFlags.Public | BindingFlags.Instance))
            .Where(p => p.Name.Contains("Pin", StringComparison.OrdinalIgnoreCase))
            .Where(p => p.PropertyType != typeof(bool) && p.PropertyType != typeof(int)
                && p.PropertyType != typeof(int?) && p.PropertyType != typeof(Fido2PinMode)
                && p.PropertyType != typeof(Fido2PinPolicy))
            .Select(p => $"{p.DeclaringType!.Name}.{p.Name}")
            .ToList();

        Assert.Empty(offenders);
    }

    [Fact]
    public void Nothing_in_the_ceremony_names_a_provider_beyond_the_opaque_tag()
    {
        // The agent must behave identically for Entra and Okta. A field that only
        // one of them fills is the first step to it not.
        var names = typeof(Fido2CeremonyRequest).GetProperties().Select(p => p.Name).ToList();

        Assert.DoesNotContain(names, n => n.Contains("Entra", StringComparison.OrdinalIgnoreCase)
            || n.Contains("Okta", StringComparison.OrdinalIgnoreCase)
            || n.Contains("Factor", StringComparison.OrdinalIgnoreCase));
        Assert.Contains("Directory", names);
    }
}
