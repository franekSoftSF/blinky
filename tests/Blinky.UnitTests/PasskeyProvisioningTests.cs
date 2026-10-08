using System.Buffers.Text;
using System.Reflection;
using System.Text;
using Blinky.Api.Passkeys;
using Blinky.Contracts;
using Blinky.Domain;
using Blinky.Domain.Entities;
using Blinky.Passkeys;
using Microsoft.Extensions.Logging.Abstractions;

namespace Blinky.UnitTests;

/// <summary>
/// 0077: the API's half of the ceremony. What these hold is order - persist before
/// the provider is asked, cancel what did not finish, delete before marking.
/// </summary>
public sealed class PasskeyProvisioningTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 8, 10, 0, 0, TimeSpan.Zero);
    private static readonly Guid AgentId = Guid.NewGuid();
    private static readonly byte[] Challenge = Encoding.ASCII.GetBytes("a challenge of decent length");
    private static readonly string ChallengeText = Base64Url.EncodeToString(Challenge);

    private readonly FakeTime time = new(Now);
    private readonly ScriptedDirectory directory = new();
    private readonly MemoryStore store = new();
    private readonly PasskeyProvisioningService service;

    public PasskeyProvisioningTests() =>
        service = new PasskeyProvisioningService(new PasskeyDirectories([directory]), store,
            NullLogger<PasskeyProvisioningService>.Instance, time);

    [Fact]
    public async Task The_provider_is_asked_only_when_the_key_is_ready_and_the_answer_is_recorded()
    {
        var job = Requested();
        Assert.Empty(directory.Calls);

        var ceremony = await service.ReadyAsync(AgentId, job.Id, Ready(job.Id), default);

        Assert.Equal(["begin"], directory.Calls);
        Assert.Equal("login.example.test", ceremony.RpId);
        Assert.Equal("https://login.example.test", ceremony.Origin);
        Assert.Equal(ChallengeText, ceremony.Challenge);
        Assert.Equal(Fido2CeremonyRequest.IdFor(job.Id, ChallengeText), ceremony.CeremonyId);
        Assert.Equal("scripted", ceremony.Directory);

        var row = store.ForJob(job.Id)!;
        Assert.Equal(PasskeyCredentialState.ChallengeIssued, row.State);
        Assert.Equal(ChallengeText, row.Challenge);
        Assert.Equal("https://login.example.test", row.Origin);
        Assert.Equal(29177301, row.TokenSerial);
    }

    [Fact]
    public async Task A_job_that_is_not_this_agents_is_refused()
    {
        var job = Requested();

        var e = await Assert.ThrowsAsync<PasskeyFlowException>(() =>
            service.ReadyAsync(Guid.NewGuid(), job.Id, Ready(job.Id), default));

        Assert.Equal(403, e.Status);
        Assert.Empty(directory.Calls);
    }

    [Fact]
    public async Task The_wrong_key_in_the_reader_is_refused_before_the_provider_is_asked()
    {
        var job = Requested(tokenSerial: 11111111);

        var e = await Assert.ThrowsAsync<PasskeyFlowException>(() =>
            service.ReadyAsync(AgentId, job.Id, Ready(job.Id), default));

        Assert.Equal("wrong-key", e.Code);
        Assert.Empty(directory.Calls);
    }

    [Fact]
    public async Task A_repeated_ready_cancels_the_challenge_it_replaces()
    {
        var job = Requested();
        await service.ReadyAsync(AgentId, job.Id, Ready(job.Id), default);

        await service.ReadyAsync(AgentId, job.Id, Ready(job.Id), default);

        // One pending registration at the provider, not two.
        Assert.Equal(["begin", "cancel:ref-1", "begin"], directory.Calls);
    }

    [Fact]
    public async Task The_row_is_provisioned_and_saved_before_the_provider_is_asked_to_register()
    {
        var (job, ceremony) = await Issued();
        directory.OnComplete = () => Assert.Equal(PasskeyCredentialState.Provisioned, store.SavedStates[^1]);

        var answer = await service.ResultAsync(AgentId, job.Id, Result(job.Id, ceremony), default);

        Assert.True(answer.Registered);
        Assert.Equal("method-1", answer.MethodId);
        var row = store.ForJob(job.Id)!;
        Assert.Equal(PasskeyCredentialState.Registered, row.State);
        Assert.Equal("method-1", row.ProviderMethodId);
        Assert.True(row.PinSetByAgent);
        Assert.Contains(store.Audit, a => a.EventType == "passkey.registered" && a.SubjectId == row.Id);
    }

    [Fact]
    public async Task The_same_result_twice_is_answered_twice_and_registered_once()
    {
        var (job, ceremony) = await Issued();
        var result = Result(job.Id, ceremony);

        await service.ResultAsync(AgentId, job.Id, result, default);
        var again = await service.ResultAsync(AgentId, job.Id, result, default);

        Assert.True(again.Registered);
        Assert.Single(directory.Calls, c => c == "complete");
    }

    [Theory]
    [InlineData("webauthn.create", "another challenge", "https://login.example.test", "different challenge")]
    [InlineData("webauthn.create", null, "https://evil.example", "origin")]
    [InlineData("webauthn.get", null, "https://login.example.test", "webauthn.get")]
    public async Task A_client_data_that_does_not_answer_what_was_issued_never_reaches_the_provider(
        string type, string? challenge, string origin, string expected)
    {
        var (job, ceremony) = await Issued();
        var clientData = ClientData(type, challenge is null ? ChallengeText : Base64Url.EncodeToString(Encoding.ASCII.GetBytes(challenge)), origin);

        var answer = await service.ResultAsync(AgentId, job.Id, Result(job.Id, ceremony) with { ClientDataJson = clientData }, default);

        Assert.False(answer.Registered);
        Assert.Contains(expected, answer.Detail);
        Assert.DoesNotContain("complete", directory.Calls);
        Assert.Contains("cancel:ref-1", directory.Calls);
        Assert.Equal(PasskeyCredentialState.Failed, store.ForJob(job.Id)!.State);
    }

    [Fact]
    public async Task An_expired_challenge_is_retryable_and_the_next_ready_gets_a_fresh_one()
    {
        var (job, ceremony) = await Issued();
        time.Now = Now.AddMinutes(11);

        var e = await Assert.ThrowsAsync<PasskeyFlowException>(() =>
            service.ResultAsync(AgentId, job.Id, Result(job.Id, ceremony), default));

        Assert.Equal("challenge-expired", e.Code);
        Assert.Equal(PasskeyCredentialState.KeyReady, store.ForJob(job.Id)!.State);
        Assert.Contains("cancel:ref-1", directory.Calls);

        var fresh = await service.ReadyAsync(AgentId, job.Id, Ready(job.Id), default);
        Assert.Equal(PasskeyCredentialState.ChallengeIssued, store.ForJob(job.Id)!.State);
        Assert.Equal(Now.AddMinutes(21), fresh.DeadlineAt);
    }

    [Fact]
    public async Task A_registration_the_provider_refuses_is_cleaned_up_and_failed()
    {
        var (job, ceremony) = await Issued();
        directory.OnComplete = () => throw new PasskeyDirectoryException("Okta: HTTP 400 - attestation rejected", 400);

        var answer = await service.ResultAsync(AgentId, job.Id, Result(job.Id, ceremony), default);

        Assert.False(answer.Registered);
        Assert.Contains("attestation rejected", answer.Detail);
        Assert.Equal(["begin", "complete", "cancel:ref-1"], directory.Calls);
        Assert.Equal(PasskeyCredentialState.Failed, store.ForJob(job.Id)!.State);
    }

    [Fact]
    public async Task A_result_for_a_replaced_challenge_is_refused()
    {
        var (job, ceremony) = await Issued();

        var e = await Assert.ThrowsAsync<PasskeyFlowException>(() => service.ResultAsync(AgentId, job.Id,
            Result(job.Id, ceremony) with { CeremonyId = Guid.NewGuid() }, default));

        Assert.Equal("stale-ceremony", e.Code);
    }

    [Fact]
    public async Task A_job_that_ends_with_the_ceremony_open_cancels_it_at_the_provider()
    {
        var (job, _) = await Issued();

        await service.JobEndedAsync(job.Id, new JobResult(job.Id, 1, false, Fido2Provisioning.Op, "key removed"), default);

        Assert.Contains("cancel:ref-1", directory.Calls);
        var row = store.ForJob(job.Id)!;
        Assert.Equal(PasskeyCredentialState.Failed, row.State);
        Assert.Contains("key removed", row.FailureReason);
    }

    [Fact]
    public async Task Revoking_deletes_at_the_provider_before_marking_the_row()
    {
        var row = await Registered();
        directory.OnDelete = () => Assert.Equal(PasskeyCredentialState.Registered, store.Get(row.Id)!.State);

        var revoked = await service.RevokeAsync(row.Id, "Key lost", "operator", default);

        Assert.Equal(PasskeyCredentialState.Revoked, revoked.State);
        Assert.Contains("delete:method-1", directory.Calls);
        Assert.Contains(store.Audit, a => a.EventType == "passkey.revoked" && a.IsExemptFromRetention);
    }

    [Fact]
    public async Task A_delete_the_provider_refuses_leaves_the_passkey_registered()
    {
        var row = await Registered();
        directory.OnDelete = () => throw new PasskeyDirectoryException("Graph: HTTP 503", 503);

        var e = await Assert.ThrowsAsync<PasskeyFlowException>(() => service.RevokeAsync(row.Id, "Key lost", "operator", default));

        Assert.Equal(502, e.Status);
        Assert.Equal(PasskeyCredentialState.Registered, store.Get(row.Id)!.State);
    }

    [Fact]
    public async Task A_method_already_gone_at_the_provider_is_revoked_and_says_so()
    {
        var row = await Registered();
        directory.OnDelete = () => throw new PasskeyDirectoryException("Graph: HTTP 404", 404);

        var revoked = await service.RevokeAsync(row.Id, "Key lost", "operator", default);

        Assert.Equal(PasskeyCredentialState.Revoked, revoked.State);
        Assert.Contains(store.Audit, a => a.EventType == "passkey.revoked" && a.Detail.Contains("\"alreadyGoneAtProvider\":true"));
    }

    [Fact]
    public async Task The_listing_shows_disagreement_instead_of_resolving_it()
    {
        var row = await Registered();
        directory.Listed =
        [
            new ProviderPasskey("someone-elses", "Their own key", Now),
        ];

        var listing = await service.ListAsync("scripted", new PasskeyUser("user-1", "alice@example.test"), default);

        Assert.Equal(PasskeyDrift.MissingAtProvider, listing.Single(l => l.Id == row.Id).Drift);
        Assert.Equal(PasskeyDrift.ProviderOnly, listing.Single(l => l.MethodId == "someone-elses").Drift);

        directory.Listed = [new ProviderPasskey("method-1", "YubiKey 29177301", Now)];
        listing = await service.ListAsync("scripted", new PasskeyUser("user-1", "alice@example.test"), default);
        Assert.Equal(PasskeyDrift.InSync, Assert.Single(listing).Drift);
    }

    [Fact]
    public async Task The_status_follows_the_ceremony_and_carries_no_pin()
    {
        var job = Requested();
        var id = store.ForJob(job.Id)!.Id;
        Assert.Equal("Requested", service.Status(id).State);

        var ceremony = await service.ReadyAsync(AgentId, job.Id, Ready(job.Id), default);
        Assert.Equal("ChallengeIssued", service.Status(id).State);
        Assert.Equal("Running", service.Status(id).JobState);

        await service.ResultAsync(AgentId, job.Id, Result(job.Id, ceremony), default);
        var status = service.Status(id);

        Assert.Equal("Registered", status.State);
        Assert.Equal("method-1", status.MethodId);
        Assert.True(status.PinSetByAgent);
        Assert.DoesNotContain(typeof(PasskeyStatus).GetProperties(),
            p => p.Name.Contains("Pin", StringComparison.Ordinal) && p.PropertyType != typeof(bool));
    }

    [Fact]
    public async Task An_unknown_user_is_refused_before_any_job_exists()
    {
        directory.User = null;

        var e = await Assert.ThrowsAsync<PasskeyFlowException>(() => service.ResolveAsync("scripted", "nobody", default));

        Assert.Equal(404, e.Status);
    }

    [Fact]
    public void Provider_delivered_pins_are_refused_where_the_provider_does_not_deliver_them()
    {
        var e = Assert.Throws<PasskeyFlowException>(() =>
            service.Check("scripted", new Fido2PinPolicy(Fido2PinMode.ProviderDelivers, 6, true)));

        Assert.Equal("pin-delivery-unsupported", e.Code);
    }

    private Job Requested(long? tokenSerial = null)
    {
        var job = new Job
        {
            Type = JobType.ProvisionFido2Credential,
            State = JobState.Running,
            AgentId = AgentId,
            TokenSerial = tokenSerial,
            DeadlineAt = Now.UtcDateTime.AddHours(1),
        };
        MemoryStore.SetId(job, Guid.NewGuid());
        store.Jobs[job.Id] = job;

        service.Record(job.Id, "scripted", new PasskeyUser("user-1", "alice@example.test"), null, tokenSerial, "operator");
        return job;
    }

    private async Task<(Job, Fido2CeremonyRequest)> Issued()
    {
        var job = Requested();
        return (job, await service.ReadyAsync(AgentId, job.Id, Ready(job.Id), default));
    }

    private async Task<PasskeyCredential> Registered()
    {
        var (job, ceremony) = await Issued();
        await service.ResultAsync(AgentId, job.Id, Result(job.Id, ceremony), default);
        return store.ForJob(job.Id)!;
    }

    private static Fido2Ready Ready(Guid jobId) => new(Protocol.Fido2SchemaVersion, jobId, 1, 29177301, "5.7.1",
        Guid.Parse("fa2b99dc-9e39-4257-8f92-4a30d23c4118"), ["FIDO_2_0", "FIDO_2_1"], true, 8, 99, true, true);

    private static Fido2CeremonyResult Result(Guid jobId, Fido2CeremonyRequest ceremony) => new(
        Protocol.Fido2SchemaVersion, jobId, ceremony.CeremonyId, 29177301,
        Guid.Parse("fa2b99dc-9e39-4257-8f92-4a30d23c4118"),
        Base64Url.EncodeToString([1, 2, 3, 4]),
        ClientData("webauthn.create", ceremony.Challenge, ceremony.Origin),
        Base64Url.EncodeToString([0xA3, 0x63, 0x66, 0x6D, 0x74]),
        "YubiKey 29177301",
        PinSetByAgent: true);

    private static string ClientData(string type, string challenge, string origin) => Base64Url.EncodeToString(
        Encoding.UTF8.GetBytes($$"""{"type":"{{type}}","challenge":"{{challenge}}","origin":"{{origin}}","crossOrigin":false}"""));

    /// <summary>A provider that does what it is told and writes down what it was asked.</summary>
    private sealed class ScriptedDirectory : IPasskeyDirectory
    {
        public List<string> Calls { get; } = [];

        public PasskeyUser? User { get; set; } = new("user-1", "alice@example.test", "Alice");

        public Action? OnComplete { get; set; }

        public Action? OnDelete { get; set; }

        public IReadOnlyList<ProviderPasskey> Listed { get; set; } = [];

        private int references;

        public string Name => "scripted";

        public PasskeyCapabilities Capabilities { get; } = new(true, false, false, true, 30);

        public Task<PasskeyUser?> FindUserAsync(string identifier, CancellationToken ct = default) =>
            Task.FromResult(User);

        public Task<PendingRegistration> BeginRegistrationAsync(PasskeyUser user, CancellationToken ct = default)
        {
            Calls.Add("begin");
            references++;

            var options = new PasskeyCreationOptions("login.example.test", "Example", "https://login.example.test",
                Challenge, [9, 9], user.Login, user.DisplayName, [-7], [], "required", "required", null,
                "direct", PasskeyExtensions.None, Now.AddMinutes(10) + (references > 1 ? TimeSpan.FromMinutes(11) : TimeSpan.Zero));

            return Task.FromResult(new PendingRegistration(user, options, "ref-1"));
        }

        public Task<RegisteredPasskey> CompleteRegistrationAsync(RegistrationHandle handle,
            AttestationResponse response, string displayName, CancellationToken ct = default)
        {
            Calls.Add("complete");
            OnComplete?.Invoke();
            return Task.FromResult(new RegisteredPasskey("method-1", Now));
        }

        public Task CancelRegistrationAsync(RegistrationHandle handle, CancellationToken ct = default)
        {
            Calls.Add($"cancel:{handle.ProviderReference}");
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<ProviderPasskey>> ListAsync(PasskeyUser user, CancellationToken ct = default) =>
            Task.FromResult(Listed);

        public Task DeleteAsync(PasskeyUser user, string methodId, CancellationToken ct = default)
        {
            Calls.Add($"delete:{methodId}");
            OnDelete?.Invoke();
            return Task.CompletedTask;
        }
    }

    private sealed class MemoryStore : IPasskeyStore
    {
        private readonly Dictionary<Guid, PasskeyCredential> rows = [];

        public Dictionary<Guid, Job> Jobs { get; } = [];

        public List<AuditEvent> Audit { get; } = [];

        /// <summary>The state of the row at each save, in order.</summary>
        public List<PasskeyCredentialState> SavedStates { get; } = [];

        public Job? Job(Guid jobId) => Jobs.GetValueOrDefault(jobId);

        public PasskeyCredential? Get(Guid id) => rows.GetValueOrDefault(id);

        public PasskeyCredential? ForJob(Guid jobId) => rows.Values.SingleOrDefault(r => r.JobId == jobId);

        public IReadOnlyList<PasskeyCredential> ForUser(string directory, string providerUserId) =>
            rows.Values.Where(r => r.Directory == directory && r.ProviderUserId == providerUserId).ToList();

        public Cardholder? Cardholder(Guid id) => null;

        public void Save(PasskeyCredential passkey, params AuditEvent[] audit)
        {
            if (passkey.Id == Guid.Empty)
            {
                SetId(passkey, Guid.NewGuid());
            }

            rows[passkey.Id] = passkey;
            SavedStates.Add(passkey.State);

            foreach (var entry in audit)
            {
                entry.SubjectId ??= passkey.Id;
                Audit.Add(entry);
            }
        }

        public static void SetId(object entity, Guid id) =>
            entity.GetType().GetProperty("Id", BindingFlags.Public | BindingFlags.Instance)!
                .SetValue(entity, id);
    }
}
