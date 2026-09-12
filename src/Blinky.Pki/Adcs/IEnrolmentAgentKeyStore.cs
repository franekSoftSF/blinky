using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Blinky.Pki.BuiltIn;

namespace Blinky.Pki.Adcs;

/// <summary>
/// The enrolment agent's certificate and key, and the only place it is used.
/// </summary>
/// <remarks>
/// <para>
/// A sibling of <see cref="ICaKeyStore"/> and for the same reason: the signature
/// happens behind the interface and the key is never handed out, so moving to a
/// PKCS#11 device is a different implementation rather than a different design.
/// It is a sibling and not the same interface because that one signs
/// certificates - it returns an <c>X509SignatureGenerator</c>, which is what
/// <c>CertificateRequest.Create</c> needs - and this one signs CMS.
/// </para>
/// <para>
/// It is deliberately <b>not</b> <c>IKeyProvider</c> from
/// <c>Blinky.Secrets</c>. That interface has exactly one operation, an HMAC,
/// because both secrets it was built for are key-derivation roots; an enrolment
/// agent signature is a CMS <c>SignerInfo</c>, and no amount of HMAC produces
/// one. Recorded because this document set said otherwise until the interface
/// could be read - docs/15-adcs-connector.md.
/// </para>
/// <para>
/// What this key is worth stating plainly: it is what lets Blinky ask a
/// Microsoft CA for a certificate in somebody else's name. ADCS will not proceed
/// without it, and there is no configuration that turns the requirement off.
/// </para>
/// </remarks>
public interface IEnrolmentAgentKeyStore : IDisposable
{
    /// <summary>The enrolment agent's own certificate.</summary>
    X509Certificate2 Certificate { get; }

    /// <summary>Where the key lives, for logs and for the console.</summary>
    string Description { get; }

    KeyCustody Custody { get; }

    /// <summary>
    /// Signs <paramref name="content"/> as CMS and returns the DER of the
    /// SignedData.
    /// </summary>
    /// <remarks>
    /// The content type travels inside <paramref name="content"/> because for
    /// CMC it is not <c>id-data</c> but <c>id-cct-PKIData</c>, and a CA that
    /// receives the wrong one rejects the request with a message about the
    /// format rather than about the content.
    /// </remarks>
    byte[] SignCms(ContentInfo content);
}

/// <summary>
/// The enrolment agent's key in an encrypted PKCS#12 beside the process.
/// </summary>
/// <remarks>
/// Refuses to load unless asked for explicitly, exactly as
/// <see cref="FileCaKeyStore"/> does. The accident being prevented is the same
/// one: nobody decides to keep this in a file, they inherit it from whatever got
/// the lab working and never look again. This key is worth at least as much as
/// the CA's, because everything it signs asserts somebody else's identity.
/// </remarks>
public sealed class FileEnrolmentAgentKeyStore : IEnrolmentAgentKeyStore
{
    /// <summary>Certificate Request Agent. Without it ADCS refuses the request.</summary>
    public const string CertificateRequestAgentEku = "1.3.6.1.4.1.311.20.2.1";

    private readonly X509Certificate2 certificate;

    private FileEnrolmentAgentKeyStore(X509Certificate2 certificate, string path)
    {
        this.certificate = certificate;
        Description = $"file: {path}";
        Custody = KeyCustody.OfFile(path);
    }

    public X509Certificate2 Certificate => certificate;

    public string Description { get; }

    public KeyCustody Custody { get; }

    /// <param name="allowFileKeys">
    /// Must be true. The parameter exists so that turning this on is a decision
    /// somebody made in configuration, and shows up in a diff.
    /// </param>
    /// <param name="now">
    /// Supplied so that a test can prove an expired certificate is refused
    /// without waiting for one to expire.
    /// </param>
    public static FileEnrolmentAgentKeyStore Open(
        string path, string? password, bool allowFileKeys, DateTimeOffset? now = null)
    {
        if (!allowFileKeys)
        {
            throw new CertificateAuthorityException(
                "A file-backed enrolment agent key is refused unless "
                + "Blinky:Adcs:AllowFileKeys is set. This key is what lets Blinky ask for a "
                + "certificate in somebody else's name; turn it on deliberately.");
        }

        if (!File.Exists(path))
        {
            throw new CertificateAuthorityException(
                $"The enrolment agent key store {path} does not exist. Enrol for an Enrollment "
                + "Agent certificate at the CA and export it with its key.");
        }

        var certificate = X509CertificateLoader.LoadPkcs12FromFile(
            path, password, X509KeyStorageFlags.Exportable);

        Require(certificate, path, now ?? DateTimeOffset.UtcNow);

        return new FileEnrolmentAgentKeyStore(certificate, path);
    }

    /// <summary>
    /// Everything that can be checked about an enrolment agent certificate
    /// before it is used, checked now rather than at somebody's enrolment.
    /// </summary>
    /// <remarks>
    /// 0033 surfaces these at backend registration, which is the earliest a
    /// person sees them. They are enforced here as well because a store that
    /// loads a useless certificate hands the failure to whoever enrols next.
    /// </remarks>
    internal static void Require(X509Certificate2 certificate, string where, DateTimeOffset now)
    {
        if (!certificate.HasPrivateKey)
        {
            throw new CertificateAuthorityException(
                $"{where} holds a certificate but no private key, so it cannot sign anything.");
        }

        if (now < certificate.NotBefore.ToUniversalTime())
        {
            throw new CertificateAuthorityException(
                $"The enrolment agent certificate in {where} is not valid until "
                + $"{certificate.NotBefore.ToUniversalTime():u}.");
        }

        if (now > certificate.NotAfter.ToUniversalTime())
        {
            throw new CertificateAuthorityException(
                $"The enrolment agent certificate in {where} expired on "
                + $"{certificate.NotAfter.ToUniversalTime():u}. ADCS refuses enrol-on-behalf-of "
                + "without a valid one, and there is no configuration that turns that off.");
        }

        if (!HasRequestAgentEku(certificate))
        {
            throw new CertificateAuthorityException(
                $"The certificate in {where} does not carry Certificate Request Agent "
                + $"({CertificateRequestAgentEku}), so a CA will not accept it as an enrolment "
                + "agent. It has to come from the Enrollment Agent template, or from Exchange "
                + "Enrollment Agent (Offline request).");
        }
    }

    /// <remarks>
    /// A certificate with no extended key usage extension at all is *not*
    /// treated as unrestricted here. That reading is correct for TLS and wrong
    /// for this: ADCS looks for the application policy on the signature, and a
    /// certificate that does not name it will be refused by the CA. Refusing it
    /// here says so in a sentence instead.
    /// </remarks>
    internal static bool HasRequestAgentEku(X509Certificate2 certificate) =>
        certificate.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .Any(extension => extension.EnhancedKeyUsages
                .Cast<System.Security.Cryptography.Oid>()
                .Any(oid => oid.Value == CertificateRequestAgentEku));

    public byte[] SignCms(ContentInfo content)
    {
        var signed = new SignedCms(content, detached: false);

        var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, certificate)
        {
            // The signer certificate and nothing above it. ADCS issued this
            // enrolment agent certificate, so it can build the rest of the
            // chain from its own store; sending it back is bytes for nothing.
            IncludeOption = X509IncludeOption.EndCertOnly,
            DigestAlgorithm = new System.Security.Cryptography.Oid("2.16.840.1.101.3.4.2.1"),
        };

        signed.ComputeSignature(signer);

        return signed.Encode();
    }

    public void Dispose() => certificate.Dispose();
}
