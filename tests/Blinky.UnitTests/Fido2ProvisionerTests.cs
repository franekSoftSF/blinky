using System.Buffers.Text;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Blinky.Contracts;
using Blinky.Fido;

namespace Blinky.UnitTests;

/// <summary>
/// 0076 without the key: the engine against a software CTAP 2.1 authenticator,
/// held to the order a real key enforces. What only hardware can prove - the
/// Yubico adapter, HID, the touch - is not here, and STATUS says so.
/// </summary>
public sealed class Fido2ProvisionerTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 8, 10, 0, 0, TimeSpan.Zero);
    private static readonly Guid JobId = Guid.NewGuid();
    private const string Challenge = "cdsZ1V10E0BGE4GcG3IK";

    private readonly List<string> log = [];
    private readonly Prompts prompts;
    private readonly Backend backend;

    public Fido2ProvisionerTests()
    {
        prompts = new Prompts(log);
        backend = new Backend(log);
    }

    private static Fido2Provisioning Provisioning(Fido2PinMode mode = Fido2PinMode.ProvisionalRandom, int min = 6,
        bool force = true, string directory = "entra") =>
        new(directory, "Jan Kowalski", new Fido2PinPolicy(mode, min, force), "YubiKey 5C NFC", true);

    private Task<Fido2Outcome> Run(IFidoKey key, Fido2Provisioning provisioning, long? serial = null) =>
        new Fido2Provisioner(prompts, backend, new FakeTime(Now)).RunAsync(key, JobId, 1, serial, provisioning, default);

    [Fact]
    public async Task A_fresh_key_is_prepared_before_the_challenge_and_finished_only_after_the_provider_says_yes()
    {
        var key = new FakeFidoKey(log);

        var outcome = await Run(key, Provisioning());

        // The order brief 12 had wrong: SetMinPINLength before, forceChangePin
        // after the provider - the other way round, MakeCredential gets no token.
        Assert.Equal(
            ["SetPin", "ShowPin", "VerifyPin", "SetMinPinLength:6", "Ready", "MakeCredential:login.example.test",
             "Touch", "Result", "ForceChangePin"],
            log);
        Assert.True(outcome.Registered);
        Assert.True(outcome.ForcedPinChange);
        Assert.True(outcome.PinSetByAgent);
        Assert.Equal("YubiKey 5C NFC 29177301", outcome.KeyName);
        Assert.True(key.ForcePinChangePending);
        Assert.Equal(key.CurrentPin, Assert.Single(prompts.Shown));
    }

    [Fact]
    public void The_fake_refuses_a_ceremony_with_a_forced_change_pending()
    {
        // The rule the order above rests on, held by the fake as a key holds it.
        var key = FakeFidoKey.WithPin(log, "482917");
        key.VerifyPin("482917");
        key.ForceChangePin();

        var e = Assert.Throws<FidoException>(() => key.MakeCredential(Request(), "482917", () => { }));

        Assert.Equal(FidoError.PinPolicyViolation, e.Error);
    }

    [Fact]
    public async Task A_refused_registration_leaves_the_pin_usable_for_the_retry()
    {
        backend.Refuse = "attestation rejected";
        var key = new FakeFidoKey(log);

        var outcome = await Run(key, Provisioning());

        Assert.False(outcome.Registered);
        Assert.DoesNotContain("ForceChangePin", log);
        Assert.False(key.ForcePinChangePending);
        Assert.Contains("attestation rejected", outcome.Warnings[^1]);
    }

    [Fact]
    public async Task A_key_with_a_pin_is_asked_for_it_and_asked_again_when_it_is_wrong()
    {
        var key = FakeFidoKey.WithPin(log, "482917");
        prompts.Current.Enqueue("111111");
        prompts.Current.Enqueue("482917");

        var outcome = await Run(key, Provisioning(Fido2PinMode.OperatorSets, force: false));

        Assert.Equal([(8, false), (7, true)], prompts.CurrentAsked);
        Assert.False(outcome.PinSetByAgent);
        Assert.Empty(prompts.Shown);
        Assert.True(outcome.Registered);
    }

    [Fact]
    public async Task Three_wrong_pins_in_a_row_stop_the_job_with_what_to_do()
    {
        var key = FakeFidoKey.WithPin(log, "482917");
        for (var i = 0; i < 4; i++)
        {
            prompts.Current.Enqueue("111111");
        }

        var e = await Assert.ThrowsAsync<FidoException>(() => Run(key, Provisioning(Fido2PinMode.OperatorSets, force: false)));

        Assert.Equal(FidoError.PinAuthBlocked, e.Error);
        Assert.Contains("put it back", e.Message);
        Assert.DoesNotContain("Ready", log);
    }

    [Fact]
    public async Task A_generated_pin_the_key_refuses_is_replaced_and_only_the_accepted_one_is_shown()
    {
        var key = new FakeFidoKey(log) { RefuseNextPin = true };

        await Run(key, Provisioning());

        Assert.Equal(2, log.Count(l => l == "SetPin"));
        Assert.Equal(key.CurrentPin, Assert.Single(prompts.Shown));
    }

    [Fact]
    public async Task A_minimum_the_key_cannot_enforce_is_refused_before_the_provider_is_asked()
    {
        var key = new FakeFidoKey(log, supportsConfig: false);

        var e = await Assert.ThrowsAsync<FidoException>(() => Run(key, Provisioning(min: 8)));

        Assert.Contains("CTAP 2.1", e.Message);
        Assert.DoesNotContain("Ready", log);
        Assert.Empty(log);
    }

    [Fact]
    public async Task Without_ctap_21_a_generated_pin_becomes_an_operator_chosen_one_and_says_so()
    {
        var key = new FakeFidoKey(log, supportsConfig: false);
        prompts.New.Enqueue("739164");

        var outcome = await Run(key, Provisioning(min: 4));

        Assert.Empty(prompts.Shown);
        Assert.Equal("739164", key.CurrentPin);
        Assert.False(outcome.ForcedPinChange);
        Assert.Contains(outcome.Warnings, w => w.Contains("cannot force a PIN change"));
    }

    [Fact]
    public async Task A_key_that_already_holds_this_users_passkey_says_so()
    {
        var key = new FakeFidoKey(log);
        key.Excludes("login.example.test", [1, 2, 3]);
        backend.Exclude = [Base64Url.EncodeToString([1, 2, 3])];

        var e = await Assert.ThrowsAsync<FidoException>(() => Run(key, Provisioning()));

        Assert.Equal(FidoError.CredentialExcluded, e.Error);
        Assert.Contains("already holds", e.Message);
    }

    [Fact]
    public async Task The_wrong_key_is_refused_before_anything_is_written()
    {
        var e = await Assert.ThrowsAsync<FidoException>(() => Run(new FakeFidoKey(log), Provisioning(), serial: 11111111));

        Assert.Contains("11111111", e.Message);
        Assert.Empty(log);
    }

    [Fact]
    public async Task The_provider_tag_changes_nothing_the_key_or_the_api_sees()
    {
        // DoD of 0077a, held here: the same job against Okta needs no change in the
        // agent, because nothing in the agent reads which provider it is.
        var entraLog = new List<string>();
        var oktaLog = new List<string>();

        var entra = await new Fido2Provisioner(new Prompts(entraLog), new Backend(entraLog), new FakeTime(Now))
            .RunAsync(new FakeFidoKey(entraLog), JobId, 1, null, Provisioning(directory: "entra"), default);
        var okta = await new Fido2Provisioner(new Prompts(oktaLog), new Backend(oktaLog), new FakeTime(Now))
            .RunAsync(new FakeFidoKey(oktaLog), JobId, 1, null, Provisioning(directory: "okta-eu"), default);

        Assert.Equal(entraLog, oktaLog);
        Assert.Equal(entra with { Warnings = [] }, okta with { Warnings = [] });
    }

    [Fact]
    public async Task Client_data_is_byte_exact_and_its_hash_is_what_the_key_signed()
    {
        var key = new FakeFidoKey(log);

        await Run(key, Provisioning());

        var clientData = Base64Url.DecodeFromChars(backend.Results[0].ClientDataJson);
        Assert.Equal(
            """{"type":"webauthn.create","challenge":"cdsZ1V10E0BGE4GcG3IK","origin":"https://login.example.test","crossOrigin":false}""",
            Encoding.UTF8.GetString(clientData));

        var attestation = new CborReader(Base64Url.DecodeFromChars(backend.Results[0].AttestationObject));
        attestation.ReadStartMap();
        Assert.Equal("fmt", attestation.ReadTextString());
        Assert.Equal("packed", attestation.ReadTextString());
        Assert.Equal("attStmt", attestation.ReadTextString());
        attestation.SkipValue();
        Assert.Equal("authData", attestation.ReadTextString());
        Assert.Equal(SHA256.HashData(clientData), attestation.ReadByteString()[..32]);
    }

    [Fact]
    public async Task No_message_to_the_api_contains_the_pin()
    {
        var key = new FakeFidoKey(log);

        await Run(key, Provisioning());

        var pin = Assert.Single(prompts.Shown);
        Assert.DoesNotContain(pin, JsonSerializer.Serialize(backend.Readies));
        Assert.DoesNotContain(pin, JsonSerializer.Serialize(backend.Results));
        Assert.True(backend.Results[0].PinSetByAgent);
        Assert.Equal(8, backend.Readies[0].PinRetries);
    }

    [Theory]
    [InlineData("123456", true)]
    [InlineData("654321", true)]
    [InlineData("890123", true)]
    [InlineData("111111", true)]
    [InlineData("112211", true)]
    [InlineData("482917", false)]
    [InlineData("1357", false)]
    public void Pins_a_key_with_complexity_rules_refuses_are_known_in_advance(string pin, bool trivial) =>
        Assert.Equal(trivial, Fido2Pin.IsTrivial(pin));

    [Fact]
    public void A_generated_pin_is_never_trivial_and_never_starts_with_zero()
    {
        for (var i = 0; i < 2000; i++)
        {
            var pin = Fido2Pin.Generate(6);

            Assert.Equal(6, pin.Length);
            Assert.NotEqual('0', pin[0]);
            Assert.False(Fido2Pin.IsTrivial(pin), pin);
            Assert.All(pin, c => Assert.True(char.IsAsciiDigit(c)));
        }
    }

    [Fact]
    public void The_attestation_statement_goes_through_as_the_key_wrote_it()
    {
        // Deliberately not canonical: keys out of order. A re-encode would sort them.
        var writer = new CborWriter(CborConformanceMode.Lax);
        writer.WriteStartMap(2);
        writer.WriteTextString("sig");
        writer.WriteByteString([9]);
        writer.WriteTextString("alg");
        writer.WriteInt32(-7);
        writer.WriteEndMap();
        var statement = writer.Encode();

        var built = AttestationObjects.Build("packed", [1, 2, 3], statement);

        Assert.True(built.AsSpan().IndexOf(statement) > 0);
    }

    private static FidoCredentialRequest Request() => new(new byte[32], "login.example.test", "Example", [1], "a", "A",
        [-7], [], true, true, false, null, false);

    private sealed class Prompts(List<string> log) : IFido2Prompts
    {
        public Queue<string> Current { get; } = new();

        public Queue<string> New { get; } = new();

        public List<(int?, bool)> CurrentAsked { get; } = [];

        public List<string> Shown { get; } = [];

        public Task<string?> AskCurrentPinAsync(int? retries, bool wrong, CancellationToken ct)
        {
            CurrentAsked.Add((retries, wrong));
            return Task.FromResult(Current.TryDequeue(out var pin) ? pin : null);
        }

        public Task<string?> AskNewPinAsync(int minLength, bool rejected, CancellationToken ct) =>
            Task.FromResult(New.TryDequeue(out var pin) ? pin : null);

        public Task ShowProvisionalPinAsync(string pin, CancellationToken ct)
        {
            log.Add("ShowPin");
            Shown.Add(pin);
            return Task.CompletedTask;
        }

        public Task TouchAsync(CancellationToken ct)
        {
            log.Add("Touch");
            return Task.CompletedTask;
        }

        public Task StatusAsync(string message, CancellationToken ct) => Task.CompletedTask;
    }

    private sealed class Backend(List<string> log) : IFido2Backend
    {
        public List<Fido2Ready> Readies { get; } = [];

        public List<Fido2CeremonyResult> Results { get; } = [];

        public string? Refuse { get; set; }

        public IReadOnlyList<string> Exclude { get; set; } = [];

        public Task<Fido2CeremonyRequest> ReadyAsync(Fido2Ready ready, CancellationToken ct)
        {
            log.Add("Ready");
            Readies.Add(ready);

            return Task.FromResult(new Fido2CeremonyRequest(
                Fido2CeremonyRequest.IdFor(ready.JobId, Challenge), ready.JobId, "opaque",
                "login.example.test", "Example", "https://login.example.test", Challenge,
                Base64Url.EncodeToString("OID:123"u8), "jan@example.test", "Jan Kowalski",
                [-7, -257], Exclude, "required", "required", "cross-platform", "direct",
                true, "userVerificationOptional", false, Now.AddMinutes(10)));
        }

        public Task<Fido2Registered> ResultAsync(Fido2CeremonyResult result, CancellationToken ct)
        {
            log.Add("Result");
            Results.Add(result);

            return Task.FromResult(Refuse is null
                ? new Fido2Registered(result.CeremonyId, true, "method-1", null)
                : new Fido2Registered(result.CeremonyId, false, null, Refuse));
        }
    }
}
