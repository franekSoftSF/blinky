using Blinky.Domain;

namespace Blinky.Pki.Adcs;

/// <summary>
/// Everything a deployment decides about one Microsoft CA. Bound from
/// <c>Blinky:Adcs</c> today.
/// </summary>
/// <remarks>
/// <para>
/// The shape <c>CaInstance.Configuration</c> is meant to hold. It is bound from
/// configuration for now because CA instances and profiles are not yet read from
/// the database - the open half of 0022 - and building the database version first
/// would have meant a schema, a migration and a console page before anybody could
/// point the API at a CA. The record is the same either way, so the move is a
/// change in where it is read from and nothing else.
/// </para>
/// <para>
/// <b>Nothing in here is key material.</b> Paths, fingerprints and a password
/// <i>file</i>, never the password itself where a file will do. A column that
/// held a PKCS#12 password would put that password in every database backup.
/// </para>
/// </remarks>
public sealed class AdcsInstanceOptions
{
    /// <summary>What the console and the logs call this CA.</summary>
    public string Name { get; set; } = "adcs";

    /// <summary>
    /// <c>Connector</c>. <c>Ces</c> is 0031 and is refused until it exists, by
    /// name, rather than accepted and failing at the first enrolment.
    /// </summary>
    public string Transport { get; set; } = "Connector";

    public AdcsConnectorOptions Connector { get; set; } = new();

    public AdcsEnrolmentAgentOptions EnrolmentAgent { get; set; } = new();

    /// <summary>
    /// Profile name to ADCS template name - <c>smartcard-logon</c> to
    /// <c>BlinkySmartcardUser</c>. The template's name, not its display name.
    /// </summary>
    public Dictionary<string, string> Templates { get; set; } = new(StringComparer.Ordinal);

    public bool AllowRevocation { get; set; } = true;
}

public sealed class AdcsConnectorOptions
{
    /// <summary><c>https://ca01.example:8444</c>. HTTPS only.</summary>
    public string? Url { get; set; }

    /// <summary>
    /// The PKCS#12 this deployment presents to the connector. Worth as much as
    /// the enrolment agent key when the connector holds the agent, because it
    /// buys that key's signature.
    /// </summary>
    public string? ClientCertificatePath { get; set; }

    /// <summary>Preferred over <see cref="ClientCertificatePassword"/>.</summary>
    public string? ClientCertificatePasswordFile { get; set; }

    public string? ClientCertificatePassword { get; set; }

    /// <summary>SHA-256 of the connector's TLS certificate.</summary>
    public string? ServerFingerprint { get; set; }

    /// <summary>A trust anchor instead of a fingerprint.</summary>
    public string? ServerCertificateAuthorityPath { get; set; }

    public string? CaConfig { get; set; }

    public int TimeoutSeconds { get; set; } = 90;
}

public sealed class AdcsEnrolmentAgentOptions
{
    /// <summary>
    /// <c>Connector</c> - the key on the Windows server, which is the arrangement
    /// for any deployment whose transport is the connector - or <c>File</c>.
    /// </summary>
    public string Location { get; set; } = "Connector";

    public string? Path { get; set; }

    public string? PasswordFile { get; set; }

    public string? Password { get; set; }

    public bool AllowFileKeys { get; set; }
}

/// <summary>
/// Turns what a deployment configured into a certificate authority, or refuses
/// with the reason.
/// </summary>
public static class AdcsInstance
{
    /// <summary>
    /// Which backend a deployment asked for. Unset is the built-in CA, which is
    /// every deployment that existed before this setting did.
    /// </summary>
    /// <remarks>
    /// An unknown value is refused at start. Falling back to the built-in CA on a
    /// typo would issue certificates from the wrong authority, and the first sign
    /// would be a workstation that does not trust them.
    /// </remarks>
    public static CaBackend Backend(string? configured)
    {
        if (string.IsNullOrWhiteSpace(configured))
        {
            return CaBackend.BuiltIn;
        }

        // Names only. Enum.TryParse also reads "1" as Adcs, and a setting that
        // switches the CA on a digit somebody typed is not one to accept.
        if (!configured.Trim().All(char.IsDigit)
            && Enum.TryParse<CaBackend>(configured.Trim(), ignoreCase: true, out var backend)
            && Enum.IsDefined(backend))
        {
            return backend;
        }

        throw new CertificateAuthorityException(
            $"Blinky:Ca:Backend is {configured}, which is neither BuiltIn nor Adcs.");
    }

    /// <param name="issues">
    /// False for a process that only revokes. It gets no enrolment agent source at
    /// all, so it cannot reach for the key even by mistake.
    /// </param>
    /// <remarks>
    /// Nothing here touches the network. The connector's enrolment agent is opened
    /// at the first enrolment, so an API starts while the Windows server is being
    /// patched and says so when it is used rather than refusing to exist. What can
    /// be checked locally - the URL, the client certificate, the pinning, a file
    /// agent's certificate - is checked now, because those are this deployment's
    /// mistakes and belong in front of whoever made them.
    /// </remarks>
    public static AdcsCertificateAuthority Create(AdcsInstanceOptions options, bool issues)
    {
        if (!string.Equals(options.Transport, "Connector", StringComparison.OrdinalIgnoreCase))
        {
            throw new CertificateAuthorityException(
                string.Equals(options.Transport, "Ces", StringComparison.OrdinalIgnoreCase)
                    ? "Blinky:Adcs:Transport is Ces, and the CES/CEP transport is patch 0031, which "
                      + "has not been written. Use Connector."
                    : $"Blinky:Adcs:Transport is {options.Transport}, which is not a transport. "
                      + "Use Connector.");
        }

        if (!Uri.TryCreate(options.Connector.Url, UriKind.Absolute, out var url)
            || url.Scheme != Uri.UriSchemeHttps)
        {
            throw new CertificateAuthorityException(
                "Blinky:Adcs:Connector:Url has to be an absolute https address. The connector "
                + "carries requests in other people's names and there is no HTTP to fall back to.");
        }

        var transport = new ConnectorAdcsTransport(new ConnectorTransportOptions(
            url,
            options.Connector.ClientCertificatePath,
            Secret(
                options.Connector.ClientCertificatePassword,
                options.Connector.ClientCertificatePasswordFile,
                "Blinky:Adcs:Connector:ClientCertificatePasswordFile"),
            options.Connector.ServerFingerprint,
            options.Connector.ServerCertificateAuthorityPath,
            options.Connector.CaConfig,
            options.Connector.TimeoutSeconds));

        try
        {
            var agents = issues ? Agents(options, transport, url) : null;

            return new AdcsCertificateAuthority(
                options.Name,
                transport,
                agents,
                new AdcsCaOptions(
                    AllowRevocation: options.AllowRevocation,
                    TemplateMap: new Dictionary<string, string>(options.Templates, StringComparer.Ordinal)));
        }
        catch
        {
            transport.Dispose();

            throw;
        }
    }

    private static IEnrolmentAgentSource Agents(
        AdcsInstanceOptions options, ConnectorAdcsTransport transport, Uri url)
    {
        var agent = options.EnrolmentAgent;

        if (string.Equals(agent.Location, "Connector", StringComparison.OrdinalIgnoreCase))
        {
            return new ConnectorEnrolmentAgentSource(transport, url.Authority);
        }

        if (string.Equals(agent.Location, "File", StringComparison.OrdinalIgnoreCase))
        {
            if (agent.Path is not { Length: > 0 } path)
            {
                throw new CertificateAuthorityException(
                    "Blinky:Adcs:EnrolmentAgent:Location is File and "
                    + "Blinky:Adcs:EnrolmentAgent:Path is not set.");
            }

            // Opened now: a file is local, and a wrong password or an expired
            // certificate is this deployment's mistake to see at start.
            return new OpenedEnrolmentAgentSource(FileEnrolmentAgentKeyStore.Open(
                path,
                Secret(agent.Password, agent.PasswordFile, "Blinky:Adcs:EnrolmentAgent:PasswordFile"),
                agent.AllowFileKeys));
        }

        throw new CertificateAuthorityException(
            $"Blinky:Adcs:EnrolmentAgent:Location is {agent.Location}, which is neither Connector "
            + "nor File.");
    }

    /// <summary>
    /// A password from its file when there is one, otherwise from the value.
    /// </summary>
    /// <remarks>
    /// The file wins, for the reason the PKCS#11 PIN already reads one: a value in
    /// the environment is readable by container inspection, by a crash dump and by
    /// whatever collects either.
    /// </remarks>
    internal static string? Secret(string? value, string? file, string setting)
    {
        if (string.IsNullOrWhiteSpace(file))
        {
            return string.IsNullOrEmpty(value) ? null : value;
        }

        if (!File.Exists(file))
        {
            throw new CertificateAuthorityException($"{setting} names {file}, which does not exist.");
        }

        return File.ReadAllText(file).TrimEnd('\r', '\n');
    }
}
