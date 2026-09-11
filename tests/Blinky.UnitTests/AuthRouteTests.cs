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
    /// A session is one of the two ways to be an operator.
    /// </summary>
    /// <remarks>
    /// The shared token stays until 0053e, because fifteen call sites and every
    /// script in scripts/ use it and there is nothing yet to replace them with.
    /// What must not happen is the session route quietly falling out and
    /// leaving the shared token as the only one again.
    /// </remarks>
    [Fact]
    public void Being_signed_in_is_enough_to_be_an_operator()
    {
        var program = SourceOf("src", "Blinky.Api", "Program.cs");

        var isOperator = Regex.Match(program,
            """static bool IsOperator\(HttpContext context, string expected\)(?<body>.*?)\n\}""",
            RegexOptions.Singleline);

        Assert.True(isOperator.Success, "IsOperator should still exist");
        Assert.Contains("context.Items", isOperator.Groups["body"].Value, StringComparison.Ordinal);
        Assert.Contains("\"operator\"", isOperator.Groups["body"].Value, StringComparison.Ordinal);
    }
}
