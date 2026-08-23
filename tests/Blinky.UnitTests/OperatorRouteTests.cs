using System.Text.RegularExpressions;
using Blinky.Api.Security;

namespace Blinky.UnitTests;

/// <summary>
/// Holds the operator route list in step with the endpoints that need it.
/// </summary>
/// <remarks>
/// AgentAuthenticationMiddleware exempts a fixed list of routes from mTLS
/// because a person at a console has no client certificate. Every endpoint
/// whose handler checks the operator token belongs on that list, and the two
/// are maintained by hand in different files.
///
/// They drifted: twelve of eighteen operator endpoints were missing, and the
/// console was refused its own API with "a verified client certificate is
/// required" - an answer about certificates for a request that never involved
/// one. What an operator saw was every status card reporting the deployment as
/// broken.
///
/// The check reads Program.cs rather than reflecting over handlers, because the
/// thing that has to hold is a property of the source: a handler that calls
/// IsOperator is an operator endpoint, whatever it does afterwards.
/// </remarks>
public class OperatorRouteTests
{
    private static string ProgramSource()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null)
        {
            var candidate = Path.Combine(directory.FullName, "src", "Blinky.Api", "Program.cs");
            if (File.Exists(candidate))
            {
                return File.ReadAllText(candidate);
            }

            directory = directory.Parent;
        }

        throw new FileNotFoundException(
            "Could not find src/Blinky.Api/Program.cs above " + AppContext.BaseDirectory);
    }

    /// <summary>
    /// Every route whose handler checks the operator token is exempt from mTLS.
    /// </summary>
    [Fact]
    public void Every_operator_endpoint_is_listed()
    {
        var source = ProgramSource();

        // Each app.MapX("/api/...", ... up to the next app.Map, which is as
        // much of a handler as this needs to see.
        var blocks = Regex.Matches(
            source,
            """app\.Map(?:Get|Post|Put|Delete|Patch)\(\s*"(?<route>/api/[^"]*)"(?<body>.*?)(?=app\.Map|\z)""",
            RegexOptions.Singleline);

        var missing = blocks
            .Where(b => b.Groups["body"].Value.Contains("IsOperator(context"))
            .Select(b => b.Groups["route"].Value)
            .Distinct()
            .Where(route => !AgentAuthenticationMiddleware.OperatorPaths.Contains(route))
            .ToList();

        Assert.True(missing.Count == 0,
            "These endpoints check the operator token but are not in "
            + "AgentAuthenticationMiddleware.OperatorPaths, so the middleware will "
            + "demand a client certificate the console cannot present:"
            + Environment.NewLine + string.Join(Environment.NewLine, missing));
    }

    /// <summary>
    /// And nothing is exempt that no longer exists.
    /// </summary>
    /// <remarks>
    /// A stale entry is not dangerous on its own - it names a route the router
    /// will never match - but it is a claim about the API that has quietly
    /// stopped being true, and it makes the list harder to trust when someone
    /// checks whether a real route is missing.
    /// </remarks>
    [Fact]
    public void Nothing_is_listed_that_is_not_a_route()
    {
        var source = ProgramSource();

        var stale = AgentAuthenticationMiddleware.OperatorPaths
            .Where(route => !source.Contains('"' + route + '"'))
            .ToList();

        Assert.True(stale.Count == 0,
            "These routes are exempt from mTLS but are not mapped anywhere:"
            + Environment.NewLine + string.Join(Environment.NewLine, stale));
    }
}
