using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Blinky.Piv.Attestation;

/// <summary>
/// The roots an attestation must chain to. Pinned, not discovered: the whole
/// point of attestation is that a key is on genuine hardware, and a trust
/// decision taken from the machine's own certificate store would let anything
/// with local administrator rights answer that question.
/// </summary>
public static class YubicoRoots
{
    /// <summary>
    /// SHA-256 of the pinned root, checked at load. A replaced file fails the
    /// build's tests rather than quietly widening what the system trusts.
    /// </summary>
    public const string PivAttestationRootSha256 =
        "63ECE914E54DD87915F34033C85AF4C0696BA1512F8ADD66CED738331207B546";

    private const string ResourceName =
        "Blinky.Piv.Attestation.yubico-piv-attestation-root.pem";

    private static readonly Lazy<X509Certificate2> Root = new(Load);

    /// <summary>
    /// <c>CN=Yubico PIV Root CA Serial 263751</c>, self-signed, valid to 2052.
    /// Obtained from developers.yubico.com and confirmed against the
    /// intermediates of three different YubiKeys before being embedded.
    /// </summary>
    public static X509Certificate2 PivAttestationRoot => Root.Value;

    /// <summary>The pinned set, ready to hand to <see cref="AttestationVerifier"/>.</summary>
    public static X509Certificate2Collection PivAttestation => [PivAttestationRoot];

    private static X509Certificate2 Load()
    {
        using var stream = typeof(YubicoRoots).GetTypeInfo().Assembly
                               .GetManifestResourceStream(ResourceName)
                           ?? throw new InvalidOperationException(
                               $"The pinned root {ResourceName} is missing from the assembly.");

        using var reader = new StreamReader(stream);
        var certificate = X509Certificate2.CreateFromPem(reader.ReadToEnd());

        var actual = Convert.ToHexString(certificate.GetCertHash(HashAlgorithmName.SHA256));
        if (!string.Equals(actual, PivAttestationRootSha256, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"The embedded Yubico root has fingerprint {actual}, expected "
                + $"{PivAttestationRootSha256}. Refusing to trust it.");
        }

        return certificate;
    }
}
