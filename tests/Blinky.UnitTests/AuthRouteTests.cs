using System.Text.RegularExpressions;
using Blinky.Api.Security;

namespace Blinky.UnitTests;

/// <summary>
/// The wiring between signing in and the middleware that guards everything.
/// </summary>
/// <remarks>
/// Written because all of it went missing once while the build stayed green: an
/// unused private method is not an error, an endpoint absent from
/// <see cref="AgentAuthenticationMiddleware.OperatorPaths"/> compiles perfectly,
/// and the result would have been a console that could not reach its own
/// sign-in and sessions that were never looked at. Nothing about that is
/// visible without running the deployment, which is too late to find out.
/// </remarks>
public class AuthRouteTests
{
    private static string SourceOf(params string[] parts)
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

        throw new FileNotFoundException(
            $"Could not find {Path.Combine(parts)} above {AppContext.BaseDirectory}");
    }

    /// <summary>
    /// Every route under /api/auth is exempt from mTLS.
    /// </summary>
    /// <remarks>
    /// They have to be: a person at a console holds no client certificate, and
    /// signing in cannot require being signed in. Missing one fails closed,
    /// which is the right direction and reads as an outage - the console is
    /// told a certificate is required for a request that never involved one.
    /// </remarks>
    [Fact]
    public void Every_auth_endpoint_is_reachable_without_a_client_certificate()
    {
        var program = SourceOf("src", "Blinky.Api", "Program.cs");

        var declared = Regex.Matches(program,
                @"app\.Map(?:Get|Post|Put|Delete|Patch)\(\s*""(?<route>/api/auth/[^""]*)""")
            .Select(m => m.Groups["route"].Value)
            .Distinct(StringComparer.Ordinal)
            .ToList();

        Assert.NotEmpty(declared);

        var missing = declared
            .Where(route => !AgentAuthenticationMiddleware.OperatorPaths.Contains(route))
            .ToList();

        Assert.True(missing.Count == 0,
            "These sign-in endpoints are not in OperatorPaths, so the middleware will demand "
            + "a client certificate for them and the console cannot sign in: "
            + string.Join(", ", missing));
    }

    /// <summary>
    /// The middleware actually resolves a session, rather than merely being
    /// able to.
    /// </summary>
    /// <remarks>
    /// This is the one that went missing. The method survived, the call did
    /// not, the build passed, and every session token would have been ignored
    /// while the shared token carried on working - which looks exactly like
    /// success until somebody asks who did something.
    /// </remarks>
    [Fact]
    public void The_middleware_resolves_a_session_on_operator_routes()
    {
        var middleware = SourceOf("src", "Blinky.Api", "Security",
            "AgentAuthenticationMiddleware.cs");

        Assert.Contains("private void ResolveSession", middleware, StringComparison.Ordinal);
        Assert.Contains("ResolveSession(context, database);", middleware, StringComparison.Ordinal);
    }

    /// <summary>
    /// A PUK disclosure records a name, not the word "operator".
    /// </summary>
    /// <remarks>
    /// That row is the record that the recovery secret for somebody's card was
    /// read out to a person over a telephone, and it is one of the two events
    /// retention may never remove. It was written with the literal
    /// <c>"operator"</c>, which turns the question "who was given it" into a
    /// row that cannot answer.
    /// <para>
    /// Checked in the source because the value is chosen at one call site and
    /// a literal is exactly the kind of thing that comes back during an
    /// unrelated edit.
    /// </para>
    /// </remarks>
    [Fact]
    public void Disclosing_a_puk_records_who_asked()
    {
        var program = SourceOf("src", "Blinky.Api", "Program.cs");

        Assert.Contains("escrow.AnswerOffline(request.Challenge, ActorFor(context))",
            program, StringComparison.Ordinal);
        Assert.DoesNotContain("AnswerOffline(request.Challenge, \"operator\")",
            program, StringComparison.Ordinal);
    }

    /// <summary>
    /// A session is the only way to be an operator.
    /// </summary>
    /// <remarks>
    /// Patch 0053e removed the shared <c>X-Blinky-Operator</c> token. It was
    /// one secret for everybody, so the audit trail could record that a
    /// credential had been revoked and never by whom, nothing expired, and
    /// taking access from one person meant taking it from all of them.
    /// <para>
    /// Checked in the source because the failure is silent: a second way in,
    /// added back for a script or for somebody's convenience, would work
    /// perfectly and quietly return this system to not knowing who did
    /// anything.
    /// </para>
    /// </remarks>
    [Fact]
    public void Only_a_session_makes_an_operator()
    {
        var program = SourceOf("src", "Blinky.Api", "Program.cs");

        Assert.Contains("static bool IsOperator(HttpContext context) =>", program,
            StringComparison.Ordinal);

        // The header as it would be read, not the name as it is explained. The
        // comment above IsOperator says the token is gone and why, and a test
        // that forbade the words would forbid recording the reason.
        Assert.DoesNotContain("Headers[\"X-Blinky-Operator\"]", program,
            StringComparison.Ordinal);
        Assert.DoesNotContain("Blinky:Operator:Token", program, StringComparison.Ordinal);
    }

    /// <summary>
    /// And the console has no second way in either.
    /// </summary>
    /// <remarks>
    /// Since 0101 it has no way in that it writes itself: the session is a
    /// cookie the browser attaches, and the one header the console adds is the
    /// anti-CSRF token, in the interceptor and nowhere else.
    /// </remarks>
    [Fact]
    public void The_console_presents_only_its_session()
    {
        var store = SourceOf("frontend", "src", "app", "core", "console.store.ts");

        Assert.DoesNotContain("X-Blinky-Operator", store, StringComparison.Ordinal);
        Assert.DoesNotContain("Authorization", store, StringComparison.Ordinal);
        Assert.DoesNotContain("headers:", store, StringComparison.Ordinal);

        var interceptor = SourceOf("frontend", "src", "app", "core", "credentials.interceptor.ts");

        Assert.Contains("withCredentials: true", interceptor, StringComparison.Ordinal);
        Assert.Contains("X-Blinky-Csrf", interceptor, StringComparison.Ordinal);
    }

    /// <summary>
    /// The session is not anywhere a script can read it.
    /// </summary>
    /// <remarks>
    /// The store used to keep it in <c>sessionStorage</c> and send it as a
    /// bearer token. Both are checked in the source rather than by behaviour,
    /// because either one coming back would work perfectly and silently undo
    /// 0101.
    /// </remarks>
    [Fact]
    public void The_session_token_never_reaches_javascript()
    {
        var store = SourceOf("frontend", "src", "app", "core", "auth.store.ts");

        Assert.DoesNotContain("sessionStorage.setItem", store, StringComparison.Ordinal);
        Assert.DoesNotContain("sessionStorage.getItem", store, StringComparison.Ordinal);
        Assert.DoesNotContain("Bearer ${", store, StringComparison.Ordinal);

        var program = SourceOf("src", "Blinky.Api", "Program.cs");

        // The sign-in response carries who you are, never the token itself.
        // Matched against the response object rather than the word, which also
        // appears where the token is put into the cookie.
        Assert.False(
            Regex.IsMatch(program, "outcome = \"signed-in\",\\s+token,"),
            "the sign-in response is handing the session token back to JavaScript");
    }
}
