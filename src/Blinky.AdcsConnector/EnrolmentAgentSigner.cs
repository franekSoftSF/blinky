using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Blinky.Contracts;

namespace Blinky.AdcsConnector;

/// <summary>
/// The enrolment agent, held on the Windows server beside the CA.
/// </summary>
/// <remarks>
/// <para>
/// This is where the key belongs when the connector is the transport. The CA
/// server is already the most trusted machine in the arrangement - whoever holds
/// it issues what they like, agent or not - so a key here adds almost nothing to
/// an attacker who has it, while the same key in a container adds a great deal.
/// And a key in the integration account's store can be non-exportable or live in
/// a TPM, which no PKCS#12 on a Docker volume can match.
/// </para>
/// <para>
/// It signs and decides nothing else. The <c>PKIData</c> is built on the
/// container side, where the cardholder and the template are chosen, and
/// <see cref="PkiDataInspection"/> refuses anything that is not exactly one
/// enrolment. Every signature is logged with the subject and the key it vouched
/// for, which is a record on the CA server that did not exist when the key lived
/// in the container.
/// </para>
/// <para>
/// The certificate rules are the same as <c>FileEnrolmentAgentKeyStore</c>'s in
/// <c>Blinky.Pki</c> and are duplicated rather than shared, because this project
/// deliberately does not reference that one. A test runs the same certificates
/// through both so they cannot drift apart unnoticed.
/// </para>
/// </remarks>
public sealed class EnrolmentAgentSigner : IDisposable
{
    public const string CertificateRequestAgentEku = "1.3.6.1.4.1.311.20.2.1";

    private const string PkiDataContentType = "1.3.6.1.5.5.7.12.2";

    private readonly X509Certificate2 certificate;

    private EnrolmentAgentSigner(X509Certificate2 certificate, string source)
    {
        this.certificate = certificate;
        Source = source;
        (Exportable, Provider) = KeyFacts(certificate);
    }

    public X509Certificate2 Certificate => certificate;

    public string Source { get; }

    /// <summary>From the key's own export policy. Null when the provider does not say.</summary>
    public bool? Exportable { get; }

    public string? Provider { get; }

    /// <summary>
    /// Loads the configured agent, or returns null when none is configured.
    /// </summary>
    /// <remarks>
    /// Throws when one is configured and unusable. A connector expected to sign
    /// that starts without being able to is found out at somebody's enrolment;
    /// refusing to start moves that to whoever installed it.
    /// </remarks>
    public static EnrolmentAgentSigner? Load(EnrolmentAgentOptions options, DateTimeOffset now)
    {
        if (!options.IsConfigured)
        {
            return null;
        }

        var (loaded, source) = options.Path is { Length: > 0 } path
            ? (FromFile(options, path), "file: " + path)
            : FromStore(options);

        Require(loaded, source, now);

        return new EnrolmentAgentSigner(loaded, source);
    }

    /// <summary>For tests: an agent certificate already in hand.</summary>
    internal static EnrolmentAgentSigner FromCertificate(
        X509Certificate2 certificate, string source, DateTimeOffset now)
    {
        Require(certificate, source, now);

        return new EnrolmentAgentSigner(certificate, source);
    }

    public AdcsEnrolmentAgentInfo Describe() => new(
        Convert.ToBase64String(certificate.RawData), Source, Exportable, Provider);

    /// <summary>
    /// Signs a <c>PKIData</c> as CMS, after establishing that it is one enrolment.
    /// </summary>
    /// <remarks>
    /// The dates are checked again at every signature. An agent certificate that
    /// was valid when the service started can expire while it runs, and ADCS
    /// would then refuse the CMC with a message about the signer rather than
    /// about the date.
    /// </remarks>
    public (byte[] SignedData, PkiDataInspection Inspected) Sign(byte[] pkiData, DateTimeOffset now)
    {
        var inspected = PkiDataInspection.Inspect(pkiData);

        RequireDates(certificate, Source, now);

        var signed = new SignedCms(
            new ContentInfo(new Oid(PkiDataContentType), pkiData), detached: false);

        var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, certificate)
        {
            // ADCS issued this certificate and builds the rest of the chain
            // from its own store.
            IncludeOption = X509IncludeOption.EndCertOnly,
            DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1"),
        };

        // Silent. A key that wants consent would otherwise wait for a window a
        // service in session 0 cannot draw; failing says so instead of hanging.
        signed.ComputeSignature(signer, silent: true);

        return (signed.Encode(), inspected);
    }

    /// <summary>
    /// Everything ADCS will refuse about an enrolment agent certificate, refused
    /// first. Kept identical to <c>FileEnrolmentAgentKeyStore.Require</c>.
    /// </summary>
    internal static void Require(X509Certificate2 candidate, string where, DateTimeOffset now)
    {
        if (!candidate.HasPrivateKey)
        {
            throw new InvalidOperationException(
                $"{where} holds a certificate but no private key this account can reach, so it "
                + "cannot sign anything. In a store, the key's ACL has to name the integration "
                + "account.");
        }

        RequireDates(candidate, where, now);

        var named = candidate.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .Any(extension => extension.EnhancedKeyUsages
                .Cast<Oid>()
                .Any(oid => oid.Value == CertificateRequestAgentEku));

        // An absent extension is refused too. It means "unrestricted" to TLS and
        // "not an enrolment agent" to ADCS, which is the reading that matters.
        if (!named)
        {
            throw new InvalidOperationException(
                $"The certificate in {where} does not carry Certificate Request Agent "
                + $"({CertificateRequestAgentEku}), so a CA will not accept it as an enrolment "
                + "agent. It has to come from the Enrollment Agent template.");
        }
    }

    private static void RequireDates(X509Certificate2 candidate, string where, DateTimeOffset now)
    {
        if (now < candidate.NotBefore.ToUniversalTime())
        {
            throw new InvalidOperationException(
                $"The enrolment agent certificate in {where} is not valid until "
                + $"{candidate.NotBefore.ToUniversalTime():u}.");
        }

        if (now > candidate.NotAfter.ToUniversalTime())
        {
            throw new InvalidOperationException(
                $"The enrolment agent certificate in {where} expired on "
                + $"{candidate.NotAfter.ToUniversalTime():u}. ADCS refuses enrol-on-behalf-of "
                + "without a valid one, and there is no configuration that turns that off.");
        }
    }

    private static X509Certificate2 FromFile(EnrolmentAgentOptions options, string path)
    {
        if (!options.AllowFileKey)
        {
            throw new InvalidOperationException(
                "Connector:EnrolmentAgent:Path is set and Connector:EnrolmentAgent:AllowFileKey "
                + "is not. The enrolment agent belongs in the integration account's store, where "
                + "its key can be non-exportable; turn the file on deliberately for a laboratory.");
        }

        return X509CertificateLoader.LoadPkcs12FromFile(path, options.Password);
    }

    private static (X509Certificate2 Certificate, string Source) FromStore(
        EnrolmentAgentOptions options)
    {
        if (!Enum.TryParse<StoreLocation>(options.StoreLocation, ignoreCase: true, out var location))
        {
            throw new InvalidOperationException(
                $"Connector:EnrolmentAgent:StoreLocation is {options.StoreLocation}, which is "
                + "neither CurrentUser nor LocalMachine.");
        }

        var wanted = ClientCertificateGate.Normalise(options.Thumbprint);

        using var store = new X509Store(StoreName.My, location);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

        // Both fingerprints, for the reason ServerCertificate.Load gives: which
        // one Windows prints depends on where it was copied from.
        foreach (var candidate in store.Certificates)
        {
            if (ClientCertificateGate.Normalise(candidate.Thumbprint) == wanted
                || ClientCertificateGate.FingerprintOf(candidate) == wanted)
            {
                return (candidate, $"store: {location}\\My");
            }
        }

        throw new InvalidOperationException(
            $"No certificate with fingerprint {wanted} is in {location}\\My for the account this "
            + "service runs as. CurrentUser is that account's own store, not the store of "
            + "whoever installed the service.");
    }

    /// <summary>
    /// Whether the key may leave, and what holds it, read from the key.
    /// </summary>
    private static (bool? Exportable, string? Provider) KeyFacts(X509Certificate2 candidate)
    {
        try
        {
            using AsymmetricAlgorithm? key =
                (AsymmetricAlgorithm?)candidate.GetRSAPrivateKey() ?? candidate.GetECDsaPrivateKey();

            return key switch
            {
                RSACng rsa => Cng(rsa.Key),
                ECDsaCng ecdsa => Cng(ecdsa.Key),
                RSACryptoServiceProvider csp => (
                    csp.CspKeyContainerInfo.Exportable, csp.CspKeyContainerInfo.ProviderName),
                _ => (null, null),
            };
        }
        catch (CryptographicException)
        {
            // Some providers - a TPM among them - decline to answer property
            // queries. Unknown is reported as unknown.
            return (null, null);
        }
    }

    private static (bool? Exportable, string? Provider) Cng(CngKey key) => (
        (key.ExportPolicy & (CngExportPolicies.AllowExport | CngExportPolicies.AllowPlaintextExport)) != 0,
        key.Provider?.Provider);

    public void Dispose() => certificate.Dispose();
}

/// <summary>
/// The connector's enrolment agent, or its absence. Registered either way so the
/// endpoints can say which.
/// </summary>
public sealed class ConnectorEnrolmentAgent(EnrolmentAgentSigner? signer)
{
    public EnrolmentAgentSigner? Signer => signer;
}
