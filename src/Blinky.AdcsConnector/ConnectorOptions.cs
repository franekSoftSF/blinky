namespace Blinky.AdcsConnector;

/// <summary>
/// Everything the connector is told. Bound from the <c>Connector</c> section.
/// </summary>
public sealed class ConnectorOptions
{
    /// <summary>
    /// Where to listen. One address, HTTPS only, and no HTTP fallback: the
    /// thing crossing this wire is a certificate request that names a person,
    /// and the client certificate is the only thing separating a caller from
    /// enrolment on somebody else's behalf.
    /// </summary>
    public string ListenUrl { get; set; } = "https://0.0.0.0:8444";

    /// <summary>
    /// <c>HOST\CA common name</c>, as <c>certutil -dump</c> prints it. Empty
    /// means ask <c>ICertConfig</c> for the default, which is right on a box
    /// with one CA and ambiguous on a box with two - so a request may override
    /// it and registration records what was resolved.
    /// </summary>
    public string? CaConfig { get; set; }

    public ServerCertificateOptions ServerCertificate { get; set; } = new();

    /// <summary>
    /// SHA-256 thumbprints of the client certificates allowed to call, upper
    /// case hex without separators.
    /// </summary>
    /// <remarks>
    /// An allowlist rather than a trusted issuer, because the set of callers is
    /// one API and stays one API. Trusting an issuer would mean every
    /// certificate that issuer ever signs can ask this connector to enrol on
    /// behalf of a stranger; a thumbprint cannot be widened by accident. The
    /// cost is that rotating the API's certificate is a configuration change
    /// here, which is why more than one may be listed - the new one is added
    /// before the old one is removed.
    /// </remarks>
    public IList<string> AllowedClientThumbprints { get; set; } = [];

    /// <summary>
    /// Templates this connector will submit against, by name. Empty means no
    /// restriction.
    /// </summary>
    /// <remarks>
    /// Defence in depth and nothing more: ADCS enforces template permissions
    /// itself and is the authority. This exists so that a connector installed
    /// for smart-card logon cannot be talked into requesting a subordinate CA
    /// certificate if the service account is over-granted, which is a thing
    /// that happens.
    /// </remarks>
    public IList<string> AllowedTemplates { get; set; } = [];

    /// <summary>
    /// How long to wait on the CA before giving up. ADCS answers in
    /// milliseconds when it is well and blocks indefinitely when its database
    /// is in trouble, and an API request that never returns is worse than a
    /// refusal that says why.
    /// </summary>
    public int RequestTimeoutSeconds { get; set; } = 60;
}

/// <summary>
/// The connector's own TLS certificate: from the machine store by thumbprint,
/// or from a file.
/// </summary>
/// <remarks>
/// The store is the right answer on a domain-joined CA, where the certificate
/// is auto-enrolled and renewed by Windows and nobody has to remember a file.
/// A file is for a lab and for a CA that is not itself in the PKI it runs.
/// The service account needs read access to the private key either way, and
/// that grant is the single most common reason a first start fails.
/// </remarks>
public sealed class ServerCertificateOptions
{
    public string? Thumbprint { get; set; }

    public string? Path { get; set; }

    public string? Password { get; set; }
}
