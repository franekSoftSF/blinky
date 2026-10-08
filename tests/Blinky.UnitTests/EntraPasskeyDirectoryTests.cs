using System.Net;
using System.Text;
using Blinky.Passkeys;
using Blinky.Passkeys.Entra;

namespace Blinky.UnitTests;

/// <summary>
/// Graph's FIDO2 provisioning, against answers shaped like Graph's.
/// </summary>
/// <remarks>
/// Not recorded from a tenant - none has been reached from here. The shapes come
/// from Graph's documentation of <c>webauthnCredentialCreationOptions</c> and from
/// KeyEnroll's tests, which were not recorded either. When a tenant is reached,
/// a captured answer replaces <see cref="CreationOptions"/> and whatever breaks is
/// the finding.
/// </remarks>
public sealed class EntraPasskeyDirectoryTests
{
    private static readonly PasskeyUser Alice = new("user-1", "alice@example.com", "Alice");
    private static readonly DateTimeOffset Now = new(2026, 10, 8, 10, 0, 0, TimeSpan.Zero);

    private const string CreationOptions = """
        {
          "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#microsoft.graph.webauthnCredentialCreationOptions",
          "challengeTimeoutDateTime": "2026-10-08T10:10:00Z",
          "publicKey": {
            "@odata.type": "#microsoft.graph.webauthnPublicKeyCredentialCreationOptions",
            "rp": { "id": "login.microsoft.com", "name": "Microsoft" },
            "user": { "id": "T0lEOjEyMw", "displayName": "Alice", "name": "alice@example.com" },
            "challenge": "QTU1MzNDNzAtNkM3Ni00NjQ4LUFCNjUtMDJDQUM",
            "pubKeyCredParams": [ { "type": "public-key", "alg": -7 }, { "type": "public-key", "alg": -257 } ],
            "timeout": 600000,
            "excludeCredentials": [ { "id": "AQID", "type": "public-key", "transports": [] } ],
            "authenticatorSelection": {
              "authenticatorAttachment": "cross-platform",
              "requireResidentKey": true,
              "userVerification": "required"
            },
            "attestation": "direct",
            "extensions": {
              "hmacCreateSecret": true,
              "enforceCredentialProtectionPolicy": false,
              "credentialProtectionPolicy": "userVerificationOptional"
            }
          }
        }
        """;

    private static (EntraPasskeyDirectory, FakeProvider, CountingAuthorization, FakeTime) Build()
    {
        var provider = new FakeProvider();
        var authorization = new CountingAuthorization();
        var time = new FakeTime(Now);
        var directory = new EntraPasskeyDirectory(new EntraOptions("TENANT", "CLIENT"),
            provider.Client, authorization, time);

        return (directory, provider, authorization, time);
    }

    [Fact]
    public async Task Graphs_answer_normalises_into_one_model()
    {
        var (directory, provider, _, _) = Build();
        provider.Answer(CreationOptions);

        var pending = await directory.BeginRegistrationAsync(Alice);
        var o = pending.Options;

        Assert.Equal(HttpMethod.Get, provider.Calls[0].Method);
        Assert.Equal(
            "https://graph.microsoft.com/v1.0/users/user-1/authentication/fido2Methods/creationOptions(challengeTimeoutInMinutes=10)",
            provider.Calls[0].Uri.ToString());

        Assert.Equal("login.microsoft.com", o.RpId);
        Assert.Equal("https://login.microsoft.com", o.Origin);
        Assert.Equal("A5533C70-6C76-4648-AB65-02CAC", Encoding.ASCII.GetString(o.Challenge));
        Assert.Equal("OID:123", Encoding.ASCII.GetString(o.UserHandle));
        Assert.Equal("alice@example.com", o.UserName);
        Assert.Equal([-7, -257], o.Algorithms);
        Assert.Equal([1, 2, 3], Assert.Single(o.ExcludeCredentials));
        Assert.Equal("required", o.ResidentKey);
        Assert.Equal("required", o.UserVerification);
        Assert.Equal("cross-platform", o.AuthenticatorAttachment);
        Assert.Equal("direct", o.Attestation);
        Assert.Equal(new PasskeyExtensions(true, "userVerificationOptional", false), o.Extensions);
        Assert.Equal(new DateTimeOffset(2026, 10, 8, 10, 10, 0, TimeSpan.Zero), o.Deadline);
        Assert.Null(pending.ProviderReference);
    }

    [Fact]
    public async Task The_origin_follows_the_rp_id_in_the_answer_and_not_a_constant()
    {
        var (directory, provider, _, _) = Build();
        provider.Answer(CreationOptions.Replace("\"id\": \"login.microsoft.com\"", "\"id\": \"login.sovereign.test\""));

        var options = (await directory.BeginRegistrationAsync(Alice)).Options;

        Assert.Equal("login.sovereign.test", options.RpId);
        Assert.Equal("https://login.sovereign.test", options.Origin);
    }

    [Fact]
    public async Task Without_a_timeout_in_the_answer_the_deadline_is_the_one_asked_for()
    {
        var (directory, provider, _, _) = Build();
        provider.Answer(CreationOptions.Replace("\"challengeTimeoutDateTime\": \"2026-10-08T10:10:00Z\",", ""));

        var options = (await directory.BeginRegistrationAsync(Alice)).Options;

        Assert.Equal(Now.AddMinutes(10), options.Deadline);
    }

    [Fact]
    public async Task The_attestation_goes_back_unpadded_and_the_name_within_thirty_characters()
    {
        var (directory, provider, _, _) = Build();
        provider.Answer(CreationOptions);
        var pending = await directory.BeginRegistrationAsync(Alice);

        provider.Answer(new { id = "m1", createdDateTime = "2026-10-08T10:01:00Z" }, HttpStatusCode.Created);
        var response = new AttestationResponse([0xFA, 0xFB, 0xFC, 0xFD], [0xFB, 0xFF, 0xFE, 1], [0xA3, 1, 2, 3, 4]);

        var registered = await directory.CompleteRegistrationAsync(pending, response,
            "A name that is far longer than thirty characters");

        var call = provider.Calls[1];
        Assert.Equal(HttpMethod.Post, call.Method);
        Assert.Equal("https://graph.microsoft.com/v1.0/users/user-1/authentication/fido2Methods", call.Uri.ToString());
        Assert.Equal(30, call.Json.GetProperty("displayName").GetString()!.Length);

        var credential = call.Json.GetProperty("publicKeyCredential");
        Assert.Equal("-vv8_Q", credential.GetProperty("id").GetString());
        Assert.Equal("-__-AQ", credential.GetProperty("response").GetProperty("clientDataJSON").GetString());
        Assert.Equal("owECAwQ", credential.GetProperty("response").GetProperty("attestationObject").GetString());

        Assert.Equal("m1", registered.MethodId);
        Assert.Equal(new DateTimeOffset(2026, 10, 8, 10, 1, 0, TimeSpan.Zero), registered.Created);
    }

    [Fact]
    public async Task Graphs_own_error_message_reaches_the_operator_with_its_status()
    {
        var (directory, provider, _, _) = Build();
        provider.Answer(new { error = new { code = "Authorization_RequestDenied", message = "Insufficient privileges" } },
            HttpStatusCode.Forbidden);

        var e = await Assert.ThrowsAsync<PasskeyDirectoryException>(() => directory.BeginRegistrationAsync(Alice));

        Assert.Contains("Insufficient privileges", e.Message);
        Assert.Equal(403, e.Status);
    }

    [Fact]
    public async Task A_refused_token_is_refreshed_once_and_the_call_repeated()
    {
        var (directory, provider, authorization, _) = Build();
        provider.Answer(status: HttpStatusCode.Unauthorized).Answer(CreationOptions);

        await directory.BeginRegistrationAsync(Alice);

        Assert.Equal([false, true], authorization.Requests);
        Assert.Equal("Bearer FRESH", provider.Calls[1].Authorization);
    }

    [Fact]
    public async Task A_second_refusal_is_not_retried_forever()
    {
        var (directory, provider, _, _) = Build();
        provider.Answer(status: HttpStatusCode.Unauthorized).Answer(status: HttpStatusCode.Unauthorized);

        var e = await Assert.ThrowsAsync<PasskeyDirectoryException>(() => directory.BeginRegistrationAsync(Alice));

        Assert.Equal(401, e.Status);
        Assert.Equal(2, provider.Calls.Count);
    }

    [Fact]
    public async Task Throttling_waits_as_long_as_it_is_told_within_a_limit()
    {
        var (directory, provider, _, time) = Build();
        provider
            .Answer(status: HttpStatusCode.TooManyRequests,
                shape: r => r.Headers.RetryAfter = new(TimeSpan.FromSeconds(7)))
            .Answer(status: HttpStatusCode.TooManyRequests,
                shape: r => r.Headers.RetryAfter = new(TimeSpan.FromMinutes(5)))
            .Answer(CreationOptions);

        await directory.BeginRegistrationAsync(Alice);

        Assert.Equal([TimeSpan.FromSeconds(7), TimeSpan.FromSeconds(30)], time.Waits);
    }

    [Fact]
    public async Task A_user_is_found_by_upn_and_then_by_mail()
    {
        var (directory, provider, _, _) = Build();
        provider
            .Answer(new { error = new { code = "Request_ResourceNotFound" } }, HttpStatusCode.NotFound)
            .Answer(new { value = new[] { new { id = "u2", userPrincipalName = "pat@x.com", displayName = "Pat O'Neil", mail = "pat.o'neil@x.com" } } });

        var user = await directory.FindUserAsync("pat.o'neil@x.com");

        Assert.Equal(new PasskeyUser("u2", "pat@x.com", "Pat O'Neil", "pat.o'neil@x.com"), user);
        Assert.Contains("mail eq 'pat.o''neil@x.com'", Uri.UnescapeDataString(provider.Calls[1].Uri.Query));
    }

    [Fact]
    public async Task A_guest_upn_is_escaped_whole()
    {
        var (directory, provider, _, _) = Build();
        provider.Answer(new { id = "g1", userPrincipalName = "bob_ext#EXT#@t.onmicrosoft.com" });

        await directory.FindUserAsync("bob_ext#EXT#@t.onmicrosoft.com");

        Assert.Contains("/users/bob_ext%23EXT%23%40t.onmicrosoft.com?", provider.Calls[0].Uri.AbsoluteUri);
    }

    [Fact]
    public async Task A_missing_permission_is_not_reported_as_no_such_user()
    {
        var (directory, provider, _, _) = Build();
        provider.Answer(new { error = new { message = "Insufficient privileges" } }, HttpStatusCode.Forbidden);

        var e = await Assert.ThrowsAsync<PasskeyDirectoryException>(() => directory.FindUserAsync("a@x.com"));

        Assert.Equal(403, e.Status);
    }

    [Fact]
    public async Task Methods_are_listed_and_deleted()
    {
        var (directory, provider, _, _) = Build();
        provider
            .Answer(new { value = new[] { new { id = "m1", displayName = "Key", createdDateTime = "2026-01-01T00:00:00Z", aaGuid = "fa2b99dc-9e39-4257-8f92-4a30d23c4118", model = "YubiKey 5 Series with NFC" } } })
            .Answer(status: HttpStatusCode.NoContent);

        var method = Assert.Single(await directory.ListAsync(Alice));
        await directory.DeleteAsync(Alice, "m1");

        Assert.Equal(("m1", "Key", "YubiKey 5 Series with NFC"), (method.MethodId, method.DisplayName, method.Model));
        Assert.Equal(Guid.Parse("fa2b99dc-9e39-4257-8f92-4a30d23c4118"), method.Aaguid);
        Assert.Equal(HttpMethod.Delete, provider.Calls[1].Method);
        Assert.EndsWith("/users/user-1/authentication/fido2Methods/m1", provider.Calls[1].Uri.ToString());
    }

    [Fact]
    public void The_relying_party_is_not_written_down_anywhere_in_the_product()
    {
        // DoD of 0073: rpId and origin come from the provider's answer. A literal
        // in the agent or the API would be the first step to the agent knowing
        // which provider it is working for, which it must not.
        var src = Path.Combine(RepositoryRoot(), "src");
        var offenders = System.IO.Directory.EnumerateFiles(src, "*.cs", SearchOption.AllDirectories)
            .Where(path => !path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}")
                && !path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}"))
            .Where(path => Path.GetFileName(path) != "EntraPasskeyDirectory.cs")
            .Where(path => File.ReadAllText(path).Contains("login.microsoft.com", StringComparison.OrdinalIgnoreCase))
            .Select(path => Path.GetRelativePath(src, path))
            .ToList();

        Assert.Empty(offenders);
    }

    private static string RepositoryRoot()
    {
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d is not null; d = d.Parent)
        {
            if (File.Exists(Path.Combine(d.FullName, "Blinky.slnx")))
            {
                return d.FullName;
            }
        }

        throw new InvalidOperationException($"No Blinky.slnx above {AppContext.BaseDirectory}");
    }
}
