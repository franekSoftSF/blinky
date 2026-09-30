using System.Security.Cryptography;
using System.Text;

namespace Blinky.Api.Security;

/// <summary>
/// Where a signed-in console's session actually lives: a cookie the browser's
/// JavaScript cannot read, and a second one it must.
/// </summary>
/// <remarks>
/// <para>
/// Until 0101 the console kept its session token in <c>sessionStorage</c> and
/// sent it as <c>Authorization: Bearer</c>. Every line of script on the page
/// could read it - and one already did something worse: a form without
/// <c>FormsModule</c> submitted natively, putting a password in the address
/// bar, from where it went to nginx's log and the browser's history. A token
/// that JavaScript can read is a token an injected script can take, and this
/// console can revoke credentials and disclose PUKs.
/// </para>
/// <para>
/// The cost taken on knowingly: a cookie the browser attaches by itself is a
/// cookie an unrelated page can make it attach, so state-changing requests
/// need a second proof. <c>SameSite=Strict</c> is the first line and
/// double-submit below is the second, because the first is enforced only by
/// the browser.
/// </para>
/// <para>
/// The shape is Winch's (its ADR 0009), which faced the same choice and wrote
/// the reasoning down first. Two of our sibling products answering this
/// differently would mean two sets of mistakes to make.
/// </para>
/// </remarks>
public static class SessionCookie
{
    /// <summary>The session itself. <c>HttpOnly</c>, so no script sees it.</summary>
    public const string Name = "blinky_session";

    /// <summary>
    /// The anti-CSRF token. Deliberately <b>not</b> <c>HttpOnly</c>.
    /// </summary>
    /// <remarks>
    /// The console has to read it and send it back in a header - that is what
    /// double-submit is. It is not an authenticating secret: it proves the
    /// request was made by a page that can read this origin's cookies, which a
    /// foreign page cannot.
    /// </remarks>
    public const string CsrfName = "blinky_csrf";

    /// <summary>The header the console echoes the anti-CSRF token in.</summary>
    public const string CsrfHeader = "X-Blinky-Csrf";

    /// <summary>A fresh anti-CSRF token. Same shape as a session token.</summary>
    public static string NewCsrfToken() =>
        SessionTokens.New();

    /// <summary>Sets both cookies after a completed sign-in.</summary>
    public static void Issue(HttpResponse response, string sessionToken, string csrfToken, DateTime expiresAt)
    {
        ArgumentNullException.ThrowIfNull(response);

        response.Cookies.Append(Name, sessionToken, Options(expiresAt, httpOnly: true));
        response.Cookies.Append(CsrfName, csrfToken, Options(expiresAt, httpOnly: false));
    }

    /// <summary>Removes both cookies when a session ends.</summary>
    public static void Clear(HttpResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);

        foreach (var name in new[] { Name, CsrfName })
        {
            response.Cookies.Delete(name, new CookieOptions
            {
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Path = "/",
            });
        }
    }

    /// <summary>The session token on this request, or null.</summary>
    public static string? TokenFrom(HttpRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        var value = request.Cookies[Name];

        return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }

    /// <summary>
    /// Whether a state-changing request carries the anti-CSRF token.
    /// </summary>
    /// <remarks>
    /// Compared in fixed time out of habit rather than need - the value is not
    /// a secret - and by bytes, because a cookie that survived a round trip
    /// through a proxy is a string whose encoding nobody should assume.
    /// </remarks>
    public static bool HasCsrf(HttpRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        var cookie = request.Cookies[CsrfName];
        var header = request.Headers[CsrfHeader].ToString();

        return !string.IsNullOrWhiteSpace(cookie)
            && !string.IsNullOrWhiteSpace(header)
            && CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(cookie),
                Encoding.UTF8.GetBytes(header));
    }

    /// <remarks>
    /// <c>Secure</c> always, including in development. The console is served
    /// over TLS by the edge, browsers allow a secure cookie on
    /// <c>localhost</c>, and a conditional flag is one somebody eventually
    /// leaves off. <c>Strict</c> rather than <c>Lax</c>: no flow exists in
    /// which another site may call this API, and <c>Lax</c> would let a
    /// top-level navigation carry the session.
    /// </remarks>
    private static CookieOptions Options(DateTime expiresAt, bool httpOnly) => new()
    {
        HttpOnly = httpOnly,
        Secure = true,
        SameSite = SameSiteMode.Strict,
        Path = "/",
        Expires = new DateTimeOffset(DateTime.SpecifyKind(expiresAt, DateTimeKind.Utc)),
    };
}
