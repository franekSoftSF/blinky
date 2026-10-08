using System.Net;
using Blinky.Passkeys;
using Blinky.Passkeys.Okta;

namespace Blinky.UnitTests;

/// <summary>
/// Okta's Factors route. The factor below is shaped like the one in KeyEnroll's
/// tests, whose author has run the same flow against a real org; it is still not
/// a capture, and is replaced by one when an org is reached from here.
/// </summary>
public sealed class OktaPasskeyDirectoryTests
{
    private static readonly PasskeyUser Alice = new("00u1", "alice@example.com", "Alice A");
    private static readonly DateTimeOffset Now = new(2026, 10, 8, 10, 0, 0, TimeSpan.Zero);

    private const string Factor = """
        {
          "id": "fwf1",
          "factorType": "webauthn",
          "provider": "FIDO",
          "status": "PENDING_ACTIVATION",
          "_embedded": {
            "activation": {
              "attestation": "direct",
              "authenticatorSelection": { "userVerification": "preferred", "requireResidentKey": false },
              "challenge": "cdsZ1V10E0BGE4GcG3IK",
              "excludeCredentials": [],
              "pubKeyCredParams": [ { "type": "public-key", "alg": -7 }, { "type": "public-key", "alg": -257 } ],
              "rp": { "name": "Acme" },
              "u2fParams": { "appid": "https://acme.okta.com" },
              "user": { "displayName": "Alice A", "name": "alice@example.com", "id": "00u15s1KDETTQMQYABRL" }
            }
          }
        }
        """;

    private static (OktaPasskeyDirectory, FakeProvider) Build(string org = "https://Acme.okta.com/")
    {
        var provider = new FakeProvider();
        var directory = new OktaPasskeyDirectory(new OktaOptions(org), provider.Client,
            new StaticAuthorization("SSWS", "TOKEN"), new FakeTime(Now));

        return (directory, provider);
    }

    [Fact]
    public async Task An_enrolled_factor_normalises_into_the_same_model_as_graph()
    {
        var (directory, provider) = Build();
        provider.Answer(Factor);

        var pending = await directory.BeginRegistrationAsync(Alice);
        var o = pending.Options;

        var call = provider.Calls[0];
        Assert.Equal("https://acme.okta.com/api/v1/users/00u1/factors", call.Uri.ToString());
        Assert.Equal("webauthn", call.Json.GetProperty("factorType").GetString());
        Assert.Equal("FIDO", call.Json.GetProperty("provider").GetString());
        Assert.Equal("SSWS TOKEN", call.Authorization);

        Assert.Equal("fwf1", pending.ProviderReference);
        Assert.Equal("acme.okta.com", o.RpId);
        Assert.Equal("Acme", o.RpName);
        Assert.Equal("https://acme.okta.com", o.Origin);
        Assert.Equal(Convert.FromBase64String("cdsZ1V10E0BGE4GcG3IK"), o.Challenge);
        Assert.Equal(Convert.FromBase64String("00u15s1KDETTQMQYABRL"), o.UserHandle);
        Assert.Equal([-7, -257], o.Algorithms);
        Assert.Empty(o.ExcludeCredentials);
        Assert.Equal("discouraged", o.ResidentKey);
        Assert.Equal("preferred", o.UserVerification);
        Assert.Equal(Now.AddMinutes(5), o.Deadline);
    }

    [Theory]
    // No rp.id: the configured custom domain is the rpId and the origin.
    [InlineData("https://login.acme.com", null, "login.acme.com", "https://login.acme.com")]
    // The answer names the same host.
    [InlineData("https://login.acme.com", "login.acme.com", "login.acme.com", "https://login.acme.com")]
    // The answer names a parent: the configured host is inside it, so it stays the origin.
    [InlineData("https://login.acme.com", "acme.com", "acme.com", "https://login.acme.com")]
    // The answer names somewhere else entirely: the answer wins.
    [InlineData("https://acme.okta.com", "id.acme.com", "id.acme.com", "https://id.acme.com")]
    public async Task The_origin_prefers_what_the_api_returns_over_what_is_configured(
        string org, string? rpId, string expectedRpId, string expectedOrigin)
    {
        var (directory, provider) = Build(org);
        provider.Answer(rpId is null ? Factor
            : Factor.Replace("\"rp\": { \"name\": \"Acme\" }", $"\"rp\": {{ \"name\": \"Acme\", \"id\": \"{rpId}\" }}"));

        var options = (await directory.BeginRegistrationAsync(Alice)).Options;

        Assert.Equal(expectedRpId, options.RpId);
        Assert.Equal(expectedOrigin, options.Origin);
    }

    [Fact]
    public async Task Activation_sends_standard_base64_under_oktas_names()
    {
        var (directory, provider) = Build();
        provider.Answer(Factor);
        var pending = await directory.BeginRegistrationAsync(Alice);

        provider.Answer(new { id = "fwf1", status = "ACTIVE", created = "2026-10-08T10:01:00.000Z" });
        var registered = await directory.CompleteRegistrationAsync(pending.Handle,
            new AttestationResponse([0xFA], [0xFB, 0xFF, 0xFE, 1], [0xA3, 1, 2, 3, 4]), "ignored");

        var call = provider.Calls[1];
        Assert.Equal("https://acme.okta.com/api/v1/users/00u1/factors/fwf1/lifecycle/activate", call.Uri.ToString());
        Assert.Equal("owECAwQ=", call.Json.GetProperty("attestation").GetString());
        Assert.Equal("+//+AQ==", call.Json.GetProperty("clientData").GetString());
        Assert.Equal("fwf1", registered.MethodId);
    }

    [Fact]
    public async Task A_factor_left_pending_after_activation_is_a_failure()
    {
        var (directory, provider) = Build();
        provider.Answer(Factor);
        var pending = await directory.BeginRegistrationAsync(Alice);
        provider.Answer(new { id = "fwf1", status = "PENDING_ACTIVATION" });

        var e = await Assert.ThrowsAsync<PasskeyDirectoryException>(() => directory.CompleteRegistrationAsync(
            pending.Handle, new AttestationResponse([1], [2], [3]), "ignored"));

        Assert.Contains("PENDING_ACTIVATION", e.Message);
    }

    [Fact]
    public async Task A_ceremony_failed_on_purpose_leaves_no_factor_behind()
    {
        var (directory, provider) = Build();
        provider.Answer(Factor);
        var pending = await directory.BeginRegistrationAsync(Alice);

        // The key was pulled out halfway. What follows is the contract 0077 holds
        // the orchestration to: a begin that does not complete is cancelled.
        provider.Answer(status: HttpStatusCode.NoContent);
        try
        {
            throw new TimeoutException("The key was not touched in time.");
        }
        catch (TimeoutException)
        {
            await directory.CancelRegistrationAsync(pending.Handle);
        }

        var call = provider.Calls[1];
        Assert.Equal(HttpMethod.Delete, call.Method);
        Assert.Equal("https://acme.okta.com/api/v1/users/00u1/factors/fwf1", call.Uri.ToString());
    }

    [Fact]
    public async Task Cancelling_a_factor_somebody_already_removed_is_not_an_error()
    {
        var (directory, provider) = Build();
        provider.Answer(Factor);
        var pending = await directory.BeginRegistrationAsync(Alice);
        provider.Answer(new { errorCode = "E0000007", errorSummary = "Not found" }, HttpStatusCode.NotFound);

        await directory.CancelRegistrationAsync(pending.Handle);
    }

    [Fact]
    public async Task A_factor_whose_options_cannot_be_read_is_deleted_before_the_error_surfaces()
    {
        var (directory, provider) = Build();
        provider.Answer(Factor.Replace("\"challenge\": \"cdsZ1V10E0BGE4GcG3IK\",", ""));
        provider.Answer(status: HttpStatusCode.NoContent);

        await Assert.ThrowsAsync<PasskeyDirectoryException>(() => directory.BeginRegistrationAsync(Alice));

        Assert.Equal(HttpMethod.Delete, provider.Calls[1].Method);
        Assert.EndsWith("/factors/fwf1", provider.Calls[1].Uri.ToString());
    }

    [Fact]
    public async Task Oktas_error_causes_are_part_of_the_message()
    {
        var (directory, provider) = Build();
        provider.Answer(new
        {
            errorSummary = "Api validation failed: factorEnrollRequest",
            errorCauses = new[] { new { errorSummary = "A factor of this type is already set up." } },
        }, HttpStatusCode.BadRequest);

        var e = await Assert.ThrowsAsync<PasskeyDirectoryException>(() => directory.BeginRegistrationAsync(Alice));

        Assert.Contains("already set up", e.Message);
        Assert.Equal(400, e.Status);
    }

    [Fact]
    public async Task Only_webauthn_factors_are_listed_and_a_pending_one_shows_as_pending()
    {
        var (directory, provider) = Build();
        provider.Answer("""
            [
              { "id": "a", "factorType": "push", "status": "ACTIVE" },
              { "id": "b", "factorType": "webauthn", "status": "ACTIVE", "created": "2026-01-01T00:00:00.000Z",
                "profile": { "authenticatorName": "YubiKey 5 NFC" } },
              { "id": "c", "factorType": "webauthn", "status": "PENDING_ACTIVATION" }
            ]
            """);

        var listed = await directory.ListAsync(Alice);

        Assert.Equal([("b", "YubiKey 5 NFC", "ACTIVE"), ("c", "", "PENDING_ACTIVATION")],
            listed.Select(f => (f.MethodId, f.DisplayName, f.Status!)));
    }

    [Fact]
    public async Task An_unknown_login_is_no_user_rather_than_an_error()
    {
        var (directory, provider) = Build();
        provider.Answer(new { errorCode = "E0000007", errorSummary = "Not found: Resource not found: x (User)" },
            HttpStatusCode.NotFound);

        Assert.Null(await directory.FindUserAsync("x"));
    }

    [Fact]
    public async Task A_user_is_found_by_login()
    {
        var (directory, provider) = Build();
        provider.Answer(new
        {
            id = "00u1",
            profile = new { login = "alice@example.com", email = "alice@example.com", firstName = "Alice", lastName = "A" },
        });

        var user = await directory.FindUserAsync("alice@example.com");

        Assert.Equal(new PasskeyUser("00u1", "alice@example.com", "Alice A", "alice@example.com"), user);
        Assert.Equal("https://acme.okta.com/api/v1/users/alice%40example.com", provider.Calls[0].Uri.AbsoluteUri);
    }

    [Fact]
    public void A_user_id_that_is_not_base64url_is_used_as_its_characters()
    {
        using var doc = System.Text.Json.JsonDocument.Parse("\"not base64!\"");

        Assert.Equal("not base64!"u8.ToArray(), OktaPasskeyDirectory.UserHandle(doc.RootElement));
    }
}
