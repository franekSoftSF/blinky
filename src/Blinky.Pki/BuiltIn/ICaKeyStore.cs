using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Blinky.Pki.BuiltIn;

/// <summary>
/// Where the issuing key lives, and the only place it is used.
/// </summary>
/// <remarks>
/// Shaped after PKCS#11 rather than after a file: the signing happens behind
/// this interface, and the key is never handed out. A file-backed store could
/// have exposed the key and been simpler; it does not, so that moving to an
/// HSM is a different implementation rather than a different design.
/// </remarks>
public interface ICaKeyStore : IDisposable
{
    /// <summary>The CA's own certificate.</summary>
    X509Certificate2 Certificate { get; }

    /// <summary>How this store keeps the key, for logs and for the console.</summary>
    string Description { get; }

    /// <summary>
    /// Signs a certificate. The generator is what .NET's
    /// <c>CertificateRequest.Create</c> needs, and returning one rather than a
    /// key is what keeps the private key inside the store.
    /// </summary>
    X509SignatureGenerator CreateSignatureGenerator();
}

/// <summary>How the issuing key is protected.</summary>
public enum CaKeyProtection
{
    /// <summary>An encrypted PKCS#12 on disk. Laptop, demo, CI.</summary>
    File,

    /// <summary>SoftHSM2 through PKCS#11. The compose default.</summary>
    SoftHsm,

    /// <summary>A real HSM through PKCS#11.</summary>
    Pkcs11,
}
