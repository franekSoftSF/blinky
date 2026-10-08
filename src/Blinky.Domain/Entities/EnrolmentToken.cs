using System.Security.Cryptography;
using System.Text;

namespace Blinky.Domain.Entities;

/// <summary>What a token may be used to enrol.</summary>
/// <remarks>
/// A workstation and an ADCS connector both arrive at the same endpoint with a
/// token and a certificate request, and the two are not interchangeable: a
/// connector's certificate buys the enrolment agent's signature, which is the
/// right to ask the Microsoft CA for a certificate in anybody's name. A token
/// handed to a rollout script must not be able to mint one of those, so the
/// purpose is part of the token rather than part of the request.
/// </remarks>
public enum EnrolmentPurpose
{
    /// <summary>A workstation agent joining the deployment.</summary>
    Agent,

    /// <summary>An ADCS connector, which is one machine and not a fleet.</summary>
    AdcsConnector,
}

/// <summary>
/// A credential that lets one machine ask to join, for a while and a few times.
/// </summary>
/// <remarks>
/// <para>
/// It replaces <c>Blinky:Enrolment:BootstrapToken</c>, which was one string in
/// <c>docker-compose.yml</c>: the same value for every machine, for the life of
/// the deployment, with no way to withdraw it short of restarting the API and
/// re-rolling every installer. A string like that ends up in a GPO, a runbook
/// and somebody's chat window, and once it is there it stays valid.
/// </para>
/// <para>
/// What a token proves is only that whoever holds it was given it. It does not
/// prove which machine is presenting it, so the defences are the ones that
/// limit the damage of it leaking: it expires, it can be spent a fixed number
/// of times, it can be tied to one domain, it can be withdrawn in a second, and
/// every use is counted where somebody can see it.
/// </para>
/// <para>
/// The shape is Winch's <c>EnrollmentToken</c>, which answered the same
/// question first. Blinky adds <see cref="Purpose"/>, because this deployment
/// enrols two kinds of machine and only one of them is a fleet.
/// </para>
/// </remarks>
public class EnrolmentToken
{
    public virtual Guid Id { get; protected set; }

    /// <summary>What it was made for, in words, for the person revoking it.</summary>
    public virtual string Name { get; set; } = string.Empty;

    public virtual EnrolmentPurpose Purpose { get; set; }

    /// <summary>
    /// SHA-256 of the token, hex. The token itself is shown once, at creation.
    /// </summary>
    /// <remarks>
    /// Hashed for the reason session tokens are: a backup or a support export
    /// must not hand over a working credential. A plain hash rather than
    /// PBKDF2, because this is 256 bits from the system generator - there is
    /// nothing to guess, so there is nothing slowness would buy.
    /// </remarks>
    public virtual string TokenHash { get; set; } = string.Empty;

    /// <summary>When it stops working. Null means never, which an operator has to choose.</summary>
    public virtual DateTime? ExpiresAt { get; set; }

    /// <summary>How many machines may use it. Null means any number.</summary>
    public virtual int? MaxUses { get; set; }

    public virtual int Uses { get; set; }

    /// <summary>
    /// The domain a machine must report to use this token, or null for any.
    /// </summary>
    /// <remarks>
    /// Not a control on its own - a machine reports its own domain - but it
    /// turns a token that leaks outside the organisation into one that also has
    /// to be presented from a machine willing to claim the right domain, and it
    /// stops a rollout token being spent by the wrong site by accident.
    /// </remarks>
    public virtual string? AllowedDomain { get; set; }

    /// <summary>The operator who created it. An audit event carries the same name.</summary>
    public virtual string CreatedBy { get; set; } = string.Empty;

    public virtual DateTime CreatedAt { get; set; }

    public virtual DateTime? RevokedAt { get; set; }

    public virtual string? RevokedBy { get; set; }

    public virtual string? RevokedReason { get; set; }

    /// <summary>Whether it may still be spent.</summary>
    public virtual bool IsUsable(DateTime now) =>
        RevokedAt is null
        && (ExpiresAt is null || ExpiresAt > now)
        && (MaxUses is null || Uses < MaxUses);

    /// <summary>Why it cannot be spent, for the console's list. Null when it can.</summary>
    public virtual string? Spent(DateTime now) =>
        RevokedAt is not null ? "revoked"
        : ExpiresAt is not null && ExpiresAt <= now ? "expired"
        : MaxUses is not null && Uses >= MaxUses ? "used up"
        : null;

    /// <summary>
    /// Why this token may not be spent on this enrolment, or null when it may.
    /// </summary>
    /// <remarks>
    /// One method rather than a chain of checks in the caller, so that the
    /// decision and the line in the log cannot disagree - and so the rules can
    /// be tested without a database.
    /// </remarks>
    public virtual string? Refusal(EnrolmentPurpose purpose, string? domain, DateTime now)
    {
        if (Purpose != purpose)
        {
            return $"token is for {Purpose}, not {purpose}";
        }

        if (Spent(now) is { } spent)
        {
            return spent;
        }

        return !string.IsNullOrWhiteSpace(AllowedDomain)
               && !string.Equals(AllowedDomain, domain, StringComparison.OrdinalIgnoreCase)
            ? $"token is tied to {AllowedDomain}"
            : null;
    }

    /// <summary>A new token: the value, which is never stored, and its hash, which is.</summary>
    public static (string Token, string Hash) Generate()
    {
        // URL-safe base64 of 32 bytes: it survives being pasted into a GPO, a
        // command line, a YAML file and an MSI property without escaping.
        var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');

        return (token, Fingerprint(token));
    }

    /// <summary>What the row holds, and what a presented token is looked up by.</summary>
    public static string Fingerprint(string token)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);

        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
    }
}

/// <summary>
/// An ADCS connector this deployment has issued a certificate to.
/// </summary>
/// <remarks>
/// <para>
/// Which client certificates are connectors used to be a fingerprint pasted
/// into <c>.env</c> as <c>ADCS_CONNECTOR_FINGERPRINT</c>: copied by hand after
/// running a tool, invisible to the console, and impossible to withdraw without
/// editing a file on the server and restarting the API. A connector's
/// certificate is worth as much as the enrolment agent's key - holding it buys
/// that key's signature - so "who may be one" belongs where it can be seen and
/// taken away.
/// </para>
/// <para>
/// The row is created by the enrolment that issued the certificate, so the
/// fingerprint is never typed by anybody. Revoking it is a transition and not a
/// delete: a connector that was trusted last week is part of what happened.
/// </para>
/// </remarks>
public class ConnectorRegistration
{
    public virtual Guid Id { get; protected set; }

    public virtual string Name { get; set; } = string.Empty;

    /// <summary>SHA-256 of the certificate, upper-case hex, as the edge reports it.</summary>
    public virtual string Fingerprint { get; set; } = string.Empty;

    /// <summary>The token it enrolled with, so a bad token's issue can be traced.</summary>
    public virtual Guid EnrolmentTokenId { get; set; }

    public virtual DateTime EnrolledAt { get; set; }

    public virtual DateTime? CertificateNotAfter { get; set; }

    public virtual DateTime? RevokedAt { get; set; }

    public virtual string? RevokedBy { get; set; }

    public virtual bool IsActive => RevokedAt is null;
}
