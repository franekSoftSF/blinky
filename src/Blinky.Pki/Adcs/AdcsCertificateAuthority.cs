using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Blinky.Contracts;
using Blinky.Domain;

namespace Blinky.Pki.Adcs;

/// <summary>
/// A Microsoft CA, driven as a registration authority.
/// </summary>
/// <remarks>
/// <para>
/// Blinky never holds a cardholder's private key and cannot prove their identity
/// to ADCS. It holds an enrolment agent certificate instead and signs a CMC on
/// their behalf; the CA validates that signature, checks the template's
/// permissions, builds the subject from Active Directory and issues. See
/// docs/04-pki-backends.md.
/// </para>
/// <para>
/// Written once for both transports. Everything protocol-specific is behind
/// <see cref="IAdcsTransport"/>, and nothing in this class knows whether it is
/// talking to CES or to the connector.
/// </para>
/// </remarks>
public sealed class AdcsCertificateAuthority(
    string name,
    IAdcsTransport transport,
    IEnrolmentAgentKeyStore agent,
    AdcsCaOptions? options = null) : ICertificateAuthority, IDisposable
{
    private readonly AdcsCaOptions settings = options ?? new AdcsCaOptions();

    public string Name => name;

    /// <summary>Where the enrolment agent's key lives, for the console.</summary>
    public string AgentDescription => agent.Description;

    /// <summary>What this is in front of, for the console.</summary>
    public string TransportDescription => transport.Description;

    public async Task<CaCapabilities> DescribeAsync(CancellationToken ct = default)
    {
        var description = await transport.DescribeAsync(ct);

        return new CaCapabilities(
            CaBackend.Adcs,

            // False, always. The template has to build the subject from Active
            // Directory, because a template that supplies it in the request
            // emits no SID extension and its certificates then fail to log
            // anybody in - docs/04. 0033 refuses to register an instance whose
            // template is configured the other way, which is what makes the
            // next line true rather than hopeful.
            SupportsSuppliedSubject: false,

            // Revocation needs *Issue and Manage Certificates* at the CA, which
            // is a separate grant from enrolment and routinely missing. Reported
            // from what the CA actually answered, so the console greys the
            // action out instead of offering a button that fails.
            SupportsRevocation: settings.AllowRevocation && description.AdminAvailable,

            // ADCS keeps its own revocation list and publishes it at its own
            // CDP. Claiming otherwise would put a link in the console to a file
            // nobody writes.
            PublishesCrl: false,

            AddsSidExtension: true,
            Algorithms: settings.Algorithms);
    }

    public async Task<IssuedCertificate> IssueAsync(
        CertificateRequestContext context, CancellationToken ct = default)
    {
        if (context.Profile.AdcsTemplateName is not { Length: > 0 } template)
        {
            throw new IssuancePolicyException(
                $"The profile {context.Profile.Name} names no ADCS template, and a Microsoft CA "
                + "issues from a template or not at all. Set AdcsTemplateName to the template's "
                + "name - not its display name.");
        }

        var cmc = await CmcRequest.CreateAsync(context.Pkcs10, agent, ct: ct);

        var answer = await transport.SubmitAsync(
            cmc, AdcsRequestFormat.Cmc, CmcRequest.TemplateAttribute(template), ct);

        return answer.Disposition switch
        {
            AdcsDisposition.Issued => Collect(answer, template),

            // Policy refused, which is a different thing from a fault: somebody
            // asked for something they may not have. The CA's own words are
            // carried through because they name which rule it was.
            AdcsDisposition.Denied => throw new IssuancePolicyException(
                Explain($"{Name} denied the request for {template}", answer)),

            // Neither success nor failure. A certificate manager has to approve
            // it, possibly tomorrow, and the request id is how it is collected
            // afterwards - which is why this is its own exception and not one of
            // the other two.
            AdcsDisposition.UnderSubmission or AdcsDisposition.Incomplete =>
                throw new IssuancePendingException(
                    Explain($"{Name} is holding request {answer.RequestId} for approval", answer),
                    answer.RequestId),

            _ => throw new CertificateAuthorityException(
                Explain($"{Name} answered {answer.Disposition}", answer)),
        };
    }

    public async Task RevokeAsync(RevocationRequest request, CancellationToken ct = default)
    {
        if (!settings.AllowRevocation)
        {
            throw new IssuancePolicyException(
                $"{Name} is registered with revocation switched off. Revoking here would leave "
                + "Blinky believing a certificate is revoked while the CA keeps listing it as "
                + "valid, which is worse than refusing.");
        }

        var answer = await transport.RevokeAsync(
            request.SerialNumber, (int)request.Reason, effectiveAt: null, ct);

        if (!answer.Revoked)
        {
            throw new CertificateAuthorityException(
                $"{Name} did not revoke {request.SerialNumber}: "
                + (answer.StatusMessage ?? "the CA gave no reason")
                + ". An account that may enrol does not thereby may manage certificates; that is "
                + "a separate grant at the CA.");
        }
    }

    /// <summary>
    /// Null, and not a stub. ADCS publishes its own revocation list at its own
    /// distribution point, and the console links that rather than pretending to
    /// own it - <see cref="CaCapabilities.PublishesCrl"/> says so too.
    /// </summary>
    public Task<CrlDocument?> GetCrlAsync(CancellationToken ct = default) =>
        Task.FromResult<CrlDocument?>(null);

    private static IssuedCertificate Collect(AdcsSubmitResponse answer, string template)
    {
        if (answer.Certificate is not { Length: > 0 } encoded)
        {
            throw new CertificateAuthorityException(
                $"The CA reported request {answer.RequestId} against {template} as issued and "
                + "returned no certificate. Nothing here can recover from that; the request id "
                + "is what to look up at the CA.");
        }

        X509Certificate2 certificate;
        try
        {
            certificate = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(encoded));
        }
        catch (Exception ex) when (ex is FormatException or System.Security.Cryptography.CryptographicException)
        {
            throw new CertificateAuthorityException(
                $"The certificate the CA returned for request {answer.RequestId} could not be "
                + "read: " + ex.Message, ex);
        }

        return new IssuedCertificate(certificate, Chain(answer, certificate));
    }

    /// <summary>
    /// The chain the CA sent, as a PKCS#7, with the leaf taken out.
    /// </summary>
    /// <remarks>
    /// The order is issuer first and anchor last, matching what the built-in CA
    /// returns, because a caller writing a chain to a card should not have to
    /// ask which backend produced it. A CA that sent no chain leaves this at the
    /// leaf alone rather than failing: the certificate is the thing the
    /// cardholder needs, and a missing chain is a trust-store problem at the
    /// workstation rather than a reason to discard an issued certificate.
    /// </remarks>
    private static IReadOnlyList<X509Certificate2> Chain(
        AdcsSubmitResponse answer, X509Certificate2 leaf)
    {
        if (answer.Chain is not { Length: > 0 } encoded)
        {
            return [leaf];
        }

        try
        {
            var signed = new SignedCms();
            signed.Decode(Convert.FromBase64String(encoded));

            List<X509Certificate2> chain = [leaf];
            chain.AddRange(signed.Certificates
                .Where(certificate => !string.Equals(
                    certificate.Thumbprint, leaf.Thumbprint, StringComparison.Ordinal)));

            return chain;
        }
        catch (Exception ex) when (ex is FormatException or System.Security.Cryptography.CryptographicException)
        {
            // Not fatal. See the remarks: the certificate is what was asked for.
            return [leaf];
        }
    }

    private static string Explain(string what, AdcsSubmitResponse answer)
    {
        var detail = answer.StatusMessage is { Length: > 0 } message
            ? ": " + message
            : string.Empty;

        var code = answer.HResult is { } hresult and not 0
            ? $" (0x{hresult:x8})"
            : string.Empty;

        return what + detail + code;
    }

    public void Dispose() => agent.Dispose();
}

/// <summary>
/// The parts of an ADCS instance that are this deployment's choice rather than
/// the CA's.
/// </summary>
/// <remarks>
/// Not yet the shape of <c>CaInstance.Configuration</c>. That column is jsonb
/// with no schema and no CRUD anywhere, and giving it one is its own change -
/// docs/15-adcs-connector.md.
/// </remarks>
/// <param name="AllowRevocation">
/// Whether this deployment permits revoking at the CA at all. Separate from
/// whether the account <i>could</i>: an estate that revokes through its own
/// change process wants Blinky to refuse rather than to succeed.
/// </param>
/// <param name="Algorithms">
/// What the template will accept. Asserted rather than discovered, because a
/// template's key requirements are not on the wire: a describe reports which
/// templates exist and not what each one demands. A wrong value here shows up as
/// a denial naming the key length, which is the CA telling the truth.
/// </param>
public sealed record AdcsCaOptions(
    bool AllowRevocation = true,
    IReadOnlySet<string>? AlgorithmSet = null)
{
    public IReadOnlySet<string> Algorithms { get; } = AlgorithmSet
        ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "RSA2048", "RSA3072", "RSA4096", "ECCP256", "ECCP384",
        };
}

/// <summary>
/// The CA took the request and has not answered it: a certificate manager has
/// to approve it first.
/// </summary>
/// <remarks>
/// Its own type because neither of the other two fits. It is not a fault, and it
/// is not a refusal - the request is alive at the CA and will become a
/// certificate if somebody approves it. The caller that can act on this is the
/// job engine, which has to keep the id and come back for it; until something
/// does, a pending request is a job that failed with a reason and a number.
/// </remarks>
public sealed class IssuancePendingException(string message, int requestId)
    : CertificateAuthorityException(message)
{
    /// <summary>What to pass to <see cref="IAdcsTransport.RetrieveAsync"/> later.</summary>
    public int RequestId { get; } = requestId;
}
