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
/// <remarks>
/// <para>
/// <b>Two roots, because Yubico has two.</b> Firmware before 5.7.4 attests under
/// <c>Yubico PIV Root CA Serial 263751</c>, and the token's F9 certificate is signed
/// by it directly. Firmware 5.7.4 and later - the 5.8.0 key enrolled into
/// ad.digitalworkspace.pl on 2026-09-14, the first here - attests under
/// <c>Yubico Attestation Root 1</c>, through two levels the card does not carry:
/// <c>Yubico Attestation Intermediate A 1</c> or <c>B 1</c>, then
/// <c>Yubico PIV Attestation A 1</c>, <c>B 1</c> or <c>B2 1</c>. With only the old
/// root pinned, that key was refused on the agent as an untrusted chain.
/// </para>
/// <para>
/// The published intermediates are handed to the chain builder as untrusted material,
/// never as anchors, and are pinned by fingerprint anyway so that a replaced file
/// fails the tests rather than changing what a path may run through.
/// </para>
/// </remarks>
public static class YubicoRoots
{
    /// <summary><c>CN=Yubico PIV Root CA Serial 263751</c>, self-signed, valid to 2052.</summary>
    public const string PivAttestationRootSha256 =
        "63ECE914E54DD87915F34033C85AF4C0696BA1512F8ADD66CED738331207B546";

    /// <summary><c>CN=Yubico Attestation Root 1</c>, self-signed, for firmware 5.7.4 and later.</summary>
    public const string AttestationRoot1Sha256 =
        "62760C6A6EF91679F454C8902B80FD009825B3F25DA90F1FBACE2EC6586CD5A8";

    /// <summary>
    /// The PIV branch of Root 1, as developers.yubico.com/PKI/yubico-intermediate.pem
    /// publishes it: the two attestation intermediates and the three PIV signing CAs.
    /// The same file's FIDO, OpenPGP, SD and YubiHSM CAs are left out - nothing here
    /// verifies those, and a path through one of them is not a PIV attestation.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, string> PivIntermediateSha256 =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["CN=Yubico Attestation Intermediate A 1"] = "4698A1D3389C3EC60016C216250F1D0439922832D65142327436376DC2942B55",
            ["CN=Yubico Attestation Intermediate B 1"] = "D4CC3F456FDAF4E7812A21AAB1DFE9D8E27D24E2FD2D6F21C9940109F0DAA754",
            ["CN=Yubico PIV Attestation A 1"] = "6DE693F05376F5D8CA29069261E1C8626C75D503BD2EDBFD75354CAD1F722870",
            ["CN=Yubico PIV Attestation B 1"] = "2D55B7998F4E42569D6D8FA382B6DC77D1DACF07358B19701163892922B17052",
            ["CN=Yubico PIV Attestation B2 1"] = "0C90B7D184A36EDF50A35F9BE935F0C5689BFDCFE5BDD073366CAFB49061A440",
        };

    private const string LegacyRootResource = "Blinky.Piv.Attestation.yubico-piv-attestation-root.pem";
    private const string Root1Resource = "Blinky.Piv.Attestation.yubico-attestation-root-1.pem";
    private const string IntermediatesResource = "Blinky.Piv.Attestation.yubico-piv-attestation-intermediates.pem";

    private static readonly Lazy<X509Certificate2> LegacyRoot =
        new(() => Pinned(Single(LegacyRootResource), PivAttestationRootSha256));

    private static readonly Lazy<X509Certificate2> Root1 =
        new(() => Pinned(Single(Root1Resource), AttestationRoot1Sha256));

    private static readonly Lazy<X509Certificate2Collection> Intermediates = new(LoadIntermediates);

    /// <summary>
    /// <c>CN=Yubico PIV Root CA Serial 263751</c>. Obtained from developers.yubico.com
    /// and confirmed against the intermediates of three different YubiKeys before
    /// being embedded.
    /// </summary>
    public static X509Certificate2 PivAttestationRoot => LegacyRoot.Value;

    /// <summary><c>CN=Yubico Attestation Root 1</c>, from developers.yubico.com/PKI/yubico-ca-1.pem.</summary>
    public static X509Certificate2 AttestationRoot1 => Root1.Value;

    /// <summary>The pinned set, ready to hand to <see cref="AttestationVerifier"/>.</summary>
    public static X509Certificate2Collection PivAttestation => [PivAttestationRoot, AttestationRoot1];

    /// <summary>What a 5.7.4-or-later chain runs through above the card's own certificate.</summary>
    public static X509Certificate2Collection PivAttestationIntermediates => Intermediates.Value;

    private static X509Certificate2Collection LoadIntermediates()
    {
        var collection = new X509Certificate2Collection();
        collection.ImportFromPem(Read(IntermediatesResource));

        if (collection.Count != PivIntermediateSha256.Count)
        {
            throw new InvalidOperationException(
                $"{IntermediatesResource} holds {collection.Count} certificates, expected "
                + $"{PivIntermediateSha256.Count}. Refusing to use it.");
        }

        foreach (var certificate in collection)
        {
            if (!PivIntermediateSha256.TryGetValue(certificate.Subject, out var expected))
            {
                throw new InvalidOperationException(
                    $"{IntermediatesResource} holds {certificate.Subject}, which is not one of the pinned "
                    + "Yubico PIV intermediates. Refusing to use it.");
            }

            Pinned(certificate, expected);
        }

        return collection;
    }

    private static X509Certificate2 Single(string resource) => X509Certificate2.CreateFromPem(Read(resource));

    private static string Read(string resource)
    {
        using var stream = typeof(YubicoRoots).GetTypeInfo().Assembly.GetManifestResourceStream(resource)
                           ?? throw new InvalidOperationException(
                               $"The pinned Yubico certificate {resource} is missing from the assembly.");

        using var reader = new StreamReader(stream);

        return reader.ReadToEnd();
    }

    private static X509Certificate2 Pinned(X509Certificate2 certificate, string expected)
    {
        var actual = Convert.ToHexString(certificate.GetCertHash(HashAlgorithmName.SHA256));

        if (!string.Equals(actual, expected, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"The embedded {certificate.Subject} has fingerprint {actual}, expected {expected}. "
                + "Refusing to trust it.");
        }

        return certificate;
    }
}
