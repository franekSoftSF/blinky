using System.Security.Cryptography.X509Certificates;
using Blinky.Domain;

namespace Blinky.Pki.BuiltIn;

/// <summary>
/// Loads a built-in CA from what <c>scripts/new-ca.sh</c> produced.
/// </summary>
public static class BuiltInCaFactory
{
    /// <summary>
    /// Reads <c>anchor.crt</c>, <c>issuing.p12</c> and <c>chain.pem</c> from a
    /// directory and works out the topology from what it finds: if the anchor
    /// and the issuer are the same certificate it is a single CA, otherwise it
    /// is two tiers.
    /// </summary>
    /// <remarks>
    /// Derived rather than configured, because a mismatch between a configured
    /// topology and the files on disk would be a setting that silently lies.
    /// </remarks>
    public static BuiltInCertificateAuthority LoadFromDirectory(string directory,
        string? password, bool allowFileKeys, TimeSpan? crlValidity = null)
    {
        var anchorPath = Path.Combine(directory, "anchor.crt");
        var issuingPath = Path.Combine(directory, "issuing.p12");

        if (!File.Exists(anchorPath) || !File.Exists(issuingPath))
        {
            throw new CertificateAuthorityException(
                $"{directory} does not hold a CA. Create one with "
                + "scripts/new-ca.sh --topology single|two-tier.");
        }

        var keyStore = FileCaKeyStore.Open(issuingPath, password, allowFileKeys);
        var anchor = X509CertificateLoader.LoadCertificateFromFile(anchorPath);

        var sameCertificate = string.Equals(anchor.Thumbprint, keyStore.Certificate.Thumbprint,
            StringComparison.Ordinal);

        var topology = sameCertificate ? CaTopology.Single : CaTopology.TwoTier;

        var chain = sameCertificate
            ? new List<X509Certificate2> { anchor }
            : [X509CertificateLoader.LoadCertificate(keyStore.Certificate.RawData), anchor];

        return new BuiltInCertificateAuthority(
            Path.GetFileName(Path.GetFullPath(directory)),
            keyStore,
            topology,
            chain,
            crlValidity is { } validity ? new InMemoryCrlStore(validity) : null);
    }
}
