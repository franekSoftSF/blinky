using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Blinky.Domain;

namespace Blinky.Pki.BuiltIn;

/// <summary>
/// A certificate authority that runs inside the process, in either of two
/// shapes: one self-signed CA, or an offline root with an online issuing CA.
/// </summary>
/// <remarks>
/// <para>
/// The topology is a property of the instance and is fixed once certificates
/// exist under it — changing it would leave issued certificates chaining to an
/// anchor this instance no longer claims. See docs/04-pki-backends.md.
/// </para>
/// <para>
/// Signing uses .NET's own X.509 stack rather than a third-party library. The
/// path that turns a request into a trusted credential is the one worth keeping
/// small.
/// </para>
/// </remarks>
public sealed class BuiltInCertificateAuthority(
    string name,
    ICaKeyStore keyStore,
    CaTopology topology,
    IReadOnlyList<X509Certificate2> chain,
    ICrlStore? crlStore = null,
    CaPublication? publication = null) : ICertificateAuthority, IDisposable
{
    /// <summary>Microsoft's smart-card logon extended key usage.</summary>
    public const string SmartCardLogonOid = "1.3.6.1.4.1.311.20.2.2";

    /// <summary>Microsoft's UPN, carried as an otherName in the SAN.</summary>
    public const string UpnOid = "1.3.6.1.4.1.311.20.2.3";

    /// <summary>
    /// szOID_NTDS_CA_SECURITY_EXT. Without it, a domain controller will not
    /// accept a certificate for logon on the UPN alone.
    /// </summary>
    public const string SidExtensionOid = "1.3.6.1.4.1.311.25.2";

    private const string SidOtherNameOid = "1.3.6.1.4.1.311.25.2.1";

    public string Name => name;

    public CaTopology Topology => topology;

    /// <summary>The trust anchor: the root in two-tier, the CA itself in single.</summary>
    public X509Certificate2 TrustAnchor => chain[^1];

    /// <summary>
    /// The certificate that signs end entities — and the one that belongs in
    /// <c>NTAuthCertificates</c>. In two-tier that is the issuing CA, not the
    /// root, and publishing the root there instead looks correct and does not
    /// work.
    /// </summary>
    public X509Certificate2 Issuer => keyStore.Certificate;

    public Task<CaCapabilities> DescribeAsync(CancellationToken ct = default) =>
        Task.FromResult(new CaCapabilities(
            CaBackend.BuiltIn,
            SupportsSuppliedSubject: true,
            SupportsRevocation: true,
            PublishesCrl: crlStore is not null,
            AddsSidExtension: true,
            Algorithms: new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "RSA2048", "RSA3072", "RSA4096", "ECCP256", "ECCP384",
            }));

    public Task<IssuedCertificate> IssueAsync(CertificateRequestContext context,
        CancellationToken ct = default)
    {
        var request = LoadRequest(context);

        // The subject comes from the cardholder, never from the request. A
        // token proves it holds a key; it does not get to choose whose
        // certificate it is.
        var subject = BuildSubject(context.Subject, context.Profile);

        var certificate = new CertificateRequest(subject, request.PublicKey,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        AddExtensions(certificate, context);

        var notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
        if (notBefore < Issuer.NotBefore)
        {
            notBefore = Issuer.NotBefore;
        }

        var notAfter = notBefore.AddDays(context.Profile.ValidityDays);
        if (notAfter > Issuer.NotAfter)
        {
            // A credential outliving its issuer stops working with nothing
            // having expired, which reads as a bug in everything else.
            notAfter = Issuer.NotAfter;
        }

        var serialNumber = RandomNumberGenerator.GetBytes(16);
        serialNumber[0] &= 0x7F;

        var issued = certificate.Create(Issuer.SubjectName, keyStore.CreateSignatureGenerator(),
            notBefore, notAfter, serialNumber);

        return Task.FromResult(new IssuedCertificate(issued, chain));
    }

    public Task RevokeAsync(RevocationRequest request, CancellationToken ct = default)
    {
        if (crlStore is null)
        {
            throw new CertificateAuthorityException(
                $"{name} has no revocation list configured, so nothing would be published.");
        }

        crlStore.Revoke(request, DateTimeOffset.UtcNow);

        return Task.CompletedTask;
    }

    public Task<CrlDocument?> GetCrlAsync(CancellationToken ct = default) =>
        Task.FromResult(crlStore?.Build(Issuer, keyStore.CreateSignatureGenerator()));

    /// <summary>
    /// Reads the request and checks it proves possession of the key. Loading
    /// verifies the signature, which is the whole point of a PKCS#10 — a
    /// request that has not been signed by its own key is a claim, not proof.
    /// </summary>
    private static CertificateRequest LoadRequest(CertificateRequestContext context)
    {
        CertificateRequest request;
        try
        {
            request = CertificateRequest.LoadSigningRequest(context.Pkcs10,
                HashAlgorithmName.SHA256,
                CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);
        }
        catch (Exception ex)
        {
            throw new CertificateAuthorityException(
                $"The certificate request could not be read: {ex.Message}", ex);
        }

        // The attestation says a key is on hardware. If the request carries a
        // different key, the attestation says nothing about this request.
        var attested = context.Attestation.PublicKeyInfo;
        var requested = request.PublicKey.ExportSubjectPublicKeyInfo();

        if (!attested.AsSpan().SequenceEqual(requested))
        {
            throw new IssuancePolicyException(
                "The attested key and the key in the request are not the same key.");
        }

        return request;
    }

    private static X500DistinguishedName BuildSubject(CardholderIdentity identity,
        IssuanceProfile profile)
    {
        if (!string.IsNullOrWhiteSpace(profile.SubjectTemplate))
        {
            var rendered = profile.SubjectTemplate
                .Replace("{displayName}", identity.DisplayName, StringComparison.Ordinal)
                .Replace("{upn}", identity.Upn ?? string.Empty, StringComparison.Ordinal);

            return new X500DistinguishedName(rendered);
        }

        return new X500DistinguishedName($"CN={identity.DisplayName}");
    }

    private void AddExtensions(CertificateRequest certificate, CertificateRequestContext context)
    {
        var profile = context.Profile;

        certificate.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, true));

        var usage = X509KeyUsageFlags.DigitalSignature;
        if (profile.SlotId.Equals("9D", StringComparison.OrdinalIgnoreCase))
        {
            // The key management slot is used to decrypt, which needs the key
            // to be an encipherment key as well.
            usage |= X509KeyUsageFlags.KeyEncipherment;
        }

        certificate.CertificateExtensions.Add(new X509KeyUsageExtension(usage, true));

        if (profile.ExtendedKeyUsages.Count > 0)
        {
            var oids = new OidCollection();
            foreach (var oid in profile.ExtendedKeyUsages)
            {
                oids.Add(new Oid(oid));
            }

            certificate.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(oids, false));
        }

        certificate.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(certificate.PublicKey, false));

        // Not required to build a chain, but every tool that shows one reads
        // it, and a certificate without it is harder to diagnose than to issue.
        //
        // The key-identifier form needs the issuer to carry a Subject Key
        // Identifier. Most CAs do - openssl adds one by default - but a CA
        // without one is legal, and refusing to issue because of a missing
        // convenience extension would be absurd. Fall back to naming the
        // issuer instead.
        certificate.CertificateExtensions.Add(BuildAuthorityKeyIdentifier());

        // Where to check whether this certificate is still good, and where to
        // find the CA that signed it. Both are optional in X.509 and neither
        // is optional in practice:
        //
        //   Without a CRL distribution point Windows reports
        //   CERT_TRUST_REVOCATION_STATUS_UNKNOWN and refuses a smart-card
        //   logon, because Microsoft requires the certificate to pass a
        //   revocation check rather than to skip one.
        //
        //   Without authority information access a machine that does not
        //   already hold the issuing CA cannot build the chain at all, and the
        //   failure it reports is about trust rather than about a missing
        //   certificate.
        //
        // Both were absent until 21 August 2026, which is what `certutil
        // -scinfo` on the first real logon attempt said, twice.
        if (publication is { } urls)
        {
            if (urls.CrlUrls.Count > 0)
            {
                certificate.CertificateExtensions.Add(
                    CertificateRevocationListBuilder.BuildCrlDistributionPointExtension(
                        urls.CrlUrls));
            }

            if (urls.CaIssuerUrls.Count > 0)
            {
                certificate.CertificateExtensions.Add(
                    new X509AuthorityInformationAccessExtension(
                        ocspUris: [], caIssuersUris: urls.CaIssuerUrls));
            }
        }

        if (profile.IncludeUpnSan)
        {
            if (string.IsNullOrWhiteSpace(context.Subject.Upn))
            {
                throw new IssuancePolicyException(
                    $"Profile {profile.Name} requires a UPN in the subject alternative name, "
                    + $"and {context.Subject.DisplayName} has none.");
            }

            certificate.CertificateExtensions.Add(BuildUpnSan(context.Subject.Upn));
        }

        if (profile.IncludeSidExtension)
        {
            if (string.IsNullOrWhiteSpace(context.Subject.ObjectSid))
            {
                // Refused rather than skipped: a certificate without it issues
                // cleanly and then fails to log anybody in, which is a far
                // worse outcome than a refusal here.
                throw new IssuancePolicyException(
                    $"Profile {profile.Name} requires the SID extension, and "
                    + $"{context.Subject.DisplayName} has no objectSid resolved. "
                    + "Without it a domain controller will not accept the certificate.");
            }

            certificate.CertificateExtensions.Add(BuildSidExtension(context.Subject.ObjectSid));
        }
    }

    private X509AuthorityKeyIdentifierExtension BuildAuthorityKeyIdentifier()
    {
        var hasSubjectKeyIdentifier = Issuer.Extensions
            .OfType<X509SubjectKeyIdentifierExtension>()
            .Any();

        return X509AuthorityKeyIdentifierExtension.CreateFromCertificate(Issuer,
            includeKeyIdentifier: hasSubjectKeyIdentifier,
            includeIssuerAndSerial: !hasSubjectKeyIdentifier);
    }

    /// <summary>
    /// The UPN as an otherName, which is the only form a domain controller
    /// looks at.
    /// </summary>
    private static X509Extension BuildUpnSan(string upn)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);

        using (writer.PushSequence())
        {
            // [0] otherName
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                writer.WriteObjectIdentifier(UpnOid);

                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    writer.WriteCharacterString(UniversalTagNumber.UTF8String, upn);
                }
            }
        }

        return new X509Extension("2.5.29.17", writer.Encode(), critical: false);
    }

    /// <summary>
    /// The SID, wrapped the way Windows expects: an otherName whose value is an
    /// OCTET STRING holding the SID as text.
    /// </summary>
    private static X509Extension BuildSidExtension(string objectSid)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);

        using (writer.PushSequence())
        {
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                writer.WriteObjectIdentifier(SidOtherNameOid);

                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    writer.WriteOctetString(System.Text.Encoding.ASCII.GetBytes(objectSid));
                }
            }
        }

        return new X509Extension(SidExtensionOid, writer.Encode(), critical: false);
    }

    public void Dispose() => keyStore.Dispose();
}
