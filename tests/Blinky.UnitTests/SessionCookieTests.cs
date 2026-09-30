using Blinky.Api.Security;
using Microsoft.AspNetCore.Http;

namespace Blinky.UnitTests;

/// <summary>
/// The console's session: in a cookie no script can read, with the second
/// proof a cookie needs.
/// </summary>
/// <remarks>
/// Written with 0101, which moved the session off <c>sessionStorage</c> and
/// the <c>Authorization</c> header. The flags are the whole of the defence, so
/// they are asserted rather than trusted: a session cookie that loses
/// <c>HttpOnly</c> is exactly the old defect back, and nothing else in the
/// system would notice.
/// </remarks>
public class SessionCookieTests
{
    private static HttpContext Signing(out HttpResponse response)
    {
        var context = new DefaultHttpContext();
        response = context.Response;

        return context;
    }

    private static IReadOnlyList<string> SetCookies(HttpResponse response) =>
        response.Headers.SetCookie.Select(value => value ?? string.Empty).ToList();

    [Fact]
    public void The_session_cookie_is_httponly_secure_and_strict()
    {
        _ = Signing(out var response);

        SessionCookie.Issue(response, "session-token", "csrf-token", DateTime.UtcNow.AddHours(8));

        var session = SetCookies(response).Single(c => c.StartsWith($"{SessionCookie.Name}=", StringComparison.Ordinal));

        Assert.Contains("httponly", session, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("secure", session, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=strict", session, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("path=/", session, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The anti-CSRF cookie is readable on purpose, and that is not a mistake
    /// waiting to be tidied away.
    /// </summary>
    [Fact]
    public void The_csrf_cookie_is_readable_by_the_page()
    {
        _ = Signing(out var response);

        SessionCookie.Issue(response, "session-token", "csrf-token", DateTime.UtcNow.AddHours(8));

        var csrf = SetCookies(response).Single(c => c.StartsWith($"{SessionCookie.CsrfName}=", StringComparison.Ordinal));

        Assert.DoesNotContain("httponly", csrf, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("secure", csrf, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=strict", csrf, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Signing_out_removes_both_cookies()
    {
        _ = Signing(out var response);

        SessionCookie.Clear(response);

        var cookies = SetCookies(response);

        Assert.Equal(2, cookies.Count);
        Assert.All(cookies, cookie => Assert.Contains("expires=Thu, 01 Jan 1970", cookie, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void A_session_is_read_from_the_cookie_and_nowhere_else()
    {
        var context = new DefaultHttpContext();
        context.Request.Headers.Authorization = "Bearer a-stolen-token";
        context.Request.Headers["X-Blinky-Session"] = "another-one";

        Assert.Null(SessionCookie.TokenFrom(context.Request));
    }

    [Theory]
    [InlineData("csrf-token", "csrf-token", true)]
    [InlineData("csrf-token", "another-token", false)]
    [InlineData("csrf-token", "", false)]
    [InlineData("", "csrf-token", false)]
    public void The_header_has_to_match_the_readable_cookie(string cookie, string header, bool accepted)
    {
        var context = new DefaultHttpContext();

        if (cookie.Length > 0)
        {
            context.Request.Headers.Cookie = $"{SessionCookie.CsrfName}={cookie}";
        }

        if (header.Length > 0)
        {
            context.Request.Headers[SessionCookie.CsrfHeader] = header;
        }

        Assert.Equal(accepted, SessionCookie.HasCsrf(context.Request));
    }

    /// <summary>
    /// Only the routes that run before a session exists are exempt.
    /// </summary>
    /// <remarks>
    /// An exemption is a hole by definition, so the list is asserted rather
    /// than reviewed: anything added to it later has to be added here too,
    /// which is the moment somebody has to say why.
    /// </remarks>
    [Fact]
    public void Nothing_but_the_sign_in_ceremony_skips_the_csrf_check()
    {
        Assert.Equal(
            ["/api/auth/password", "/api/auth/sign-in", "/api/auth/totp/enrol"],
            AgentAuthenticationMiddleware.CsrfExemptPaths.Order());

        Assert.All(
            AgentAuthenticationMiddleware.CsrfExemptPaths,
            path => Assert.Contains(path, AgentAuthenticationMiddleware.OperatorPaths));
    }
}
