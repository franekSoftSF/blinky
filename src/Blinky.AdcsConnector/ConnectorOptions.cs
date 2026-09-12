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
    /// The enrolment agent this connector signs CMCs with. Unset means it signs
    /// nothing and <c>/connector/sign</c> refuses, which is correct for a
    /// connector whose deployment keeps the key in the container.
    /// </summary>
    public EnrolmentAgentOptions EnrolmentAgent { get; set; } = new();

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

/// <summary>
/// Where the enrolment agent's certificate and key are: a Windows store by
/// fingerprint, or a file.
/// </summary>
/// <remarks>
/// <para>
/// The store is the point of putting the key on this server at all. The
/// certificate is issued to the integration account the connector runs as, so
/// it lands in that account's personal store, and a key there can be marked
/// non-exportable - or live in a TPM - which no file in a container can match.
/// </para>
/// <para>
/// Strong private key protection must be off. It asks for consent in a window,
/// a service in session 0 cannot draw one, and the symptom is a signature call
/// that fails with a message about a UI that does not exist.
/// </para>
/// </remarks>
public sealed class EnrolmentAgentOptions
{
    /// <summary>SHA-1 or SHA-256, any separators.</summary>
    public string? Thumbprint { get; set; }

    /// <summary>
    /// <c>CurrentUser</c> - the integration account's own store, loaded by the
    /// service control manager when it starts the service - or
    /// <c>LocalMachine</c>, where the key's ACL then has to name the account.
    /// </summary>
    public string StoreLocation { get; set; } = "CurrentUser";

    /// <summary>A PKCS#12 instead of the store. For a laboratory.</summary>
    public string? Path { get; set; }

    public string? Password { get; set; }

    /// <summary>
    /// Must be true for <see cref="Path"/> to be accepted, for the reason every
    /// other file-held key in Blinky has the same switch: nobody decides to keep
    /// this in a file, they inherit it from whatever got the lab working.
    /// </summary>
    public bool AllowFileKey { get; set; }

    public bool IsConfigured =>
        !string.IsNullOrWhiteSpace(Thumbprint) || !string.IsNullOrWhiteSpace(Path);
}
