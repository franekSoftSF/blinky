using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Blinky.Pki.BuiltIn;

/// <summary>
/// The issuing key in an encrypted PKCS#12 next to the process that uses it.
/// </summary>
/// <remarks>
/// Refuses to load unless it is asked for explicitly. The accident this
/// prevents is a demo configuration reaching production - not because a file is
/// always wrong, but because nobody ever decides to use one; they inherit it
/// from a tutorial and never look again.
/// </remarks>
public sealed class FileCaKeyStore : ICaKeyStore
{
    private readonly X509Certificate2 certificate;

    private FileCaKeyStore(X509Certificate2 certificate, string path)
    {
        this.certificate = certificate;
        Description = $"file: {path}";
        Custody = KeyCustody.OfFile(path);
    }

    public X509Certificate2 Certificate => certificate;

    public string Description { get; }

    /// <inheritdoc />
    /// <remarks>
    /// Reported as not production-ready, deliberately and every time. A console
    /// that looks the same whether the key is in a file or in a device is a
    /// console that lets a laboratory arrangement reach a fleet unnoticed.
    /// </remarks>
    public KeyCustody Custody { get; private set; } = KeyCustody.OfFile("(not opened)");

    /// <summary>
    /// Opens a PKCS#12 holding the CA certificate and its key.
    /// </summary>
    /// <param name="allowFileKeys">
    /// Must be true. The parameter exists so that turning this on is a decision
    /// someone made in configuration, and shows up in a diff.
    /// </param>
    public static FileCaKeyStore Open(string path, string? password, bool allowFileKeys)
    {
        if (!allowFileKeys)
        {
            throw new CertificateAuthorityException(
                "A file-backed CA key is refused unless Blinky:Ca:AllowFileKeys is set. "
                + "Use SoftHSM or a PKCS#11 device, or turn it on deliberately.");
        }

        if (!File.Exists(path))
        {
            throw new CertificateAuthorityException(
                $"The CA key store {path} does not exist. Create one with scripts/new-ca.sh.");
        }

        var certificate = X509CertificateLoader.LoadPkcs12FromFile(path, password,
            X509KeyStorageFlags.Exportable);

        if (!certificate.HasPrivateKey)
        {
            throw new CertificateAuthorityException(
                $"{path} holds a certificate but no private key, so it cannot sign anything.");
        }

        return new FileCaKeyStore(certificate, path);
    }

    public X509SignatureGenerator CreateSignatureGenerator()
    {
        if (certificate.GetRSAPrivateKey() is { } rsa)
        {
            return X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pkcs1);
        }

        if (certificate.GetECDsaPrivateKey() is { } ecdsa)
        {
            return X509SignatureGenerator.CreateForECDsa(ecdsa);
        }

        throw new CertificateAuthorityException(
            "The CA key is neither RSA nor ECDSA, and nothing else can sign here.");
    }

    public void Dispose() => certificate.Dispose();
}
