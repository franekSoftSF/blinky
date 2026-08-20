using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Blinky.Piv;
using Blinky.Piv.Attestation;

namespace Blinky.UnitTests;

/// <summary>
/// Attestation is verified against a synthetic Yubico-shaped PKI built here,
/// not against certificates captured from the tokens on the bench. A real
/// attestation certificate names one physical device - it carries the serial
/// in an extension - and this repository is public. The genuine-hardware half
/// of the check is `tools/PivProbe`, which verifies a live token against the
/// pinned root and prints the verdict; the result is recorded in STATUS.md.
/// </summary>
public sealed class AttestationVerifierTests
{
    private const uint TokenSerial = 29177301;

    [Fact]
    public void A_well_formed_attestation_verifies()
    {
        var pki = SyntheticYubico.Build();

        var result = new AttestationVerifier(pki.Roots)
            .Verify(pki.Leaf, pki.Intermediate, PivSlot.Authentication, TokenSerial);

        Assert.True(result.IsTrusted, result.Explanation);
        Assert.Equal(AttestationFailure.None, result.Failure);
        Assert.Equal(TokenSerial, result.Attestation!.SerialNumber);
    }

    [Fact]
    public void A_self_signed_forgery_is_rejected()
    {
        // The shape an attacker reaches for first: a certificate carrying all
        // the right Yubico extensions, signed by nobody in particular. Every
        // field in it is a lie the chain check never gets far enough to read.
        var pki = SyntheticYubico.Build();
        var forgery = SyntheticYubico.SelfSignedImposter(TokenSerial);

        var result = new AttestationVerifier(pki.Roots)
            .Verify(forgery, forgery, PivSlot.Authentication, TokenSerial);

        Assert.False(result.IsTrusted);
        Assert.Equal(AttestationFailure.UntrustedChain, result.Failure);
    }

    [Fact]
    public void A_chain_to_the_wrong_root_is_rejected()
    {
        // A complete, internally consistent PKI - just not Yubico's. This is
        // what pinning is for.
        var genuine = SyntheticYubico.Build();
        var impostor = SyntheticYubico.Build();

        var result = new AttestationVerifier(genuine.Roots)
            .Verify(impostor.Leaf, impostor.Intermediate, PivSlot.Authentication, TokenSerial);

        Assert.False(result.IsTrusted);
        Assert.Equal(AttestationFailure.UntrustedChain, result.Failure);
    }

    [Fact]
    public void A_serial_mismatch_is_rejected()
    {
        // A genuine attestation, from a different token. Without this check an
        // attacker could present one real YubiKey's attestation while a second
        // device holds the key.
        var pki = SyntheticYubico.Build();

        var result = new AttestationVerifier(pki.Roots)
            .Verify(pki.Leaf, pki.Intermediate, PivSlot.Authentication, expectedSerial: 12345678);

        Assert.False(result.IsTrusted);
        Assert.Equal(AttestationFailure.SerialMismatch, result.Failure);
        Assert.Contains("29177301", result.Explanation, StringComparison.Ordinal);
    }

    [Fact]
    public void An_attestation_for_another_slot_is_rejected()
    {
        // 9E has no PIN policy at all. Accepting its attestation for a 9A
        // credential would certify a key that anyone holding the token can use.
        var pki = SyntheticYubico.Build();

        var result = new AttestationVerifier(pki.Roots)
            .Verify(pki.Leaf, pki.Intermediate, PivSlot.CardAuthentication, TokenSerial);

        Assert.False(result.IsTrusted);
        Assert.Equal(AttestationFailure.SlotMismatch, result.Failure);
    }

    [Fact]
    public void An_attestation_of_a_different_key_is_rejected()
    {
        // The attestation says "this key is on hardware". If it is not the key
        // in the request, it says nothing about the request.
        var pki = SyntheticYubico.Build();
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var result = new AttestationVerifier(pki.Roots).Verify(
            pki.Leaf, pki.Intermediate, PivSlot.Authentication, TokenSerial,
            other.ExportSubjectPublicKeyInfo());

        Assert.False(result.IsTrusted);
        Assert.Equal(AttestationFailure.PublicKeyMismatch, result.Failure);
    }

    [Fact]
    public void The_attested_key_matches_when_it_is_the_same_key()
    {
        var pki = SyntheticYubico.Build();

        var result = new AttestationVerifier(pki.Roots).Verify(
            pki.Leaf, pki.Intermediate, PivSlot.Authentication, TokenSerial,
            pki.Leaf.PublicKey.ExportSubjectPublicKeyInfo());

        Assert.True(result.IsTrusted, result.Explanation);
    }

    [Fact]
    public void An_ordinary_certificate_is_not_an_attestation()
    {
        var pki = SyntheticYubico.Build();
        var plain = SyntheticYubico.PlainCertificate();

        var result = new AttestationVerifier(pki.Roots)
            .Verify(plain, pki.Intermediate, PivSlot.Authentication, TokenSerial);

        Assert.False(result.IsTrusted);
        Assert.Equal(AttestationFailure.NotAnAttestation, result.Failure);
    }

    [Fact]
    public void Verifying_against_no_roots_is_refused_rather_than_accepting_everything()
    {
        Assert.Throws<ArgumentException>(() => new AttestationVerifier([]));
    }

    [Fact]
    public void The_extensions_are_read_off_the_certificate()
    {
        var pki = SyntheticYubico.Build();

        var attestation = YubicoAttestation.Parse(pki.Leaf);

        Assert.Equal(new FirmwareVersion(5, 7, 1), attestation.Firmware);
        Assert.Equal(TokenSerial, attestation.SerialNumber);
        Assert.Equal(PinPolicy.Once, attestation.PinPolicy);
        Assert.Equal(TouchPolicy.Never, attestation.TouchPolicy);
        Assert.Equal(FormFactor.UsbCKeychain, attestation.FormFactor);
        Assert.False(attestation.IsFipsDevice);
        Assert.Equal(PivSlot.Authentication.Id, attestation.Slot!.Value.Id);
    }

    [Fact]
    public void A_fips_device_is_recognised_from_the_high_bit()
    {
        var pki = SyntheticYubico.Build(formFactor: 0x83);

        var attestation = YubicoAttestation.Parse(pki.Leaf);

        Assert.True(attestation.IsFipsDevice);
        Assert.Equal(FormFactor.UsbCKeychain, attestation.FormFactor);
    }

    [Theory]
    [InlineData(PinPolicy.Always, null, AttestationFailure.PolicyNotSatisfied)]
    [InlineData(PinPolicy.Once, null, AttestationFailure.None)]
    [InlineData(null, TouchPolicy.Always, AttestationFailure.PolicyNotSatisfied)]
    [InlineData(null, TouchPolicy.Never, AttestationFailure.None)]
    public void A_profile_can_demand_policies_the_key_was_generated_with(
        PinPolicy? requiredPin, TouchPolicy? requiredTouch, AttestationFailure expected)
    {
        // A profile that demands touch cannot be satisfied by a key generated
        // without it, and the key cannot be changed after generation.
        var pki = SyntheticYubico.Build();
        var verified = new AttestationVerifier(pki.Roots)
            .Verify(pki.Leaf, pki.Intermediate, PivSlot.Authentication, TokenSerial);

        var result = AttestationVerifier.RequirePolicies(verified, requiredPin, requiredTouch);

        Assert.Equal(expected, result.Failure);
    }

    [Fact]
    public void The_pinned_root_is_the_one_yubico_publishes()
    {
        // If the embedded file is ever replaced, this fails rather than the
        // system quietly trusting a new issuer.
        var root = YubicoRoots.PivAttestationRoot;

        Assert.Equal("CN=Yubico PIV Root CA Serial 263751", root.Subject);
        Assert.Equal(root.Subject, root.Issuer);
        Assert.Equal(YubicoRoots.PivAttestationRootSha256,
            Convert.ToHexString(root.GetCertHash(HashAlgorithmName.SHA256)));
    }
}

/// <summary>
/// A three-level PKI shaped like Yubico's: self-signed root, an intermediate,
/// and a leaf carrying the Yubico attestation extensions.
/// </summary>
internal static class SyntheticYubico
{
    internal sealed record Pki(
        X509Certificate2 Leaf,
        X509Certificate2 Intermediate,
        X509Certificate2Collection Roots);

    public static Pki Build(uint serial = 29177301, byte formFactor = 0x03,
        string slotName = "9a")
    {
        // Yubico's real attestation certificates run to 2052; what matters
        // here is only that the window contains now, because the verifier
        // checks validity and should.
        var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        var notAfter = DateTimeOffset.UtcNow.AddYears(20);

        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var rootRequest = new CertificateRequest("CN=Synthetic PIV Root", rootKey,
            HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 1, true));
        rootRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        var root = rootRequest.CreateSelfSigned(notBefore, notAfter);

        using var intermediateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var intermediateRequest = new CertificateRequest("CN=Synthetic PIV Attestation",
            intermediateKey, HashAlgorithmName.SHA256);
        intermediateRequest.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(true, true, 0, true));
        intermediateRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        var intermediate = intermediateRequest.Create(root, notBefore, notAfter, [0x01]);
        var intermediateWithKey = intermediate.CopyWithPrivateKey(intermediateKey);

        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var leafRequest = new CertificateRequest($"CN=YubiKey PIV Attestation {slotName}",
            leafKey, HashAlgorithmName.SHA256);
        AddYubicoExtensions(leafRequest, serial, formFactor);
        var leaf = leafRequest.Create(intermediateWithKey, notBefore, notAfter, [0x02]);

        return new Pki(leaf, intermediate, [root]);
    }

    /// <summary>All the right extensions, signed by nobody.</summary>
    public static X509Certificate2 SelfSignedImposter(uint serial)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=YubiKey PIV Attestation 9a", key,
            HashAlgorithmName.SHA256);
        AddYubicoExtensions(request, serial, 0x03);

        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(20));
    }

    public static X509Certificate2 PlainCertificate()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=not an attestation", key,
            HashAlgorithmName.SHA256);

        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(20));
    }

    private static void AddYubicoExtensions(CertificateRequest request, uint serial,
        byte formFactor)
    {
        request.CertificateExtensions.Add(
            new X509Extension("1.3.6.1.4.1.41482.3.3", [0x05, 0x07, 0x01], false));

        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteInteger(serial);
        request.CertificateExtensions.Add(
            new X509Extension("1.3.6.1.4.1.41482.3.7", writer.Encode(), false));

        // PIN policy Once, touch policy Never - what ykman generated on the bench.
        request.CertificateExtensions.Add(
            new X509Extension("1.3.6.1.4.1.41482.3.8", [0x02, 0x01], false));

        request.CertificateExtensions.Add(
            new X509Extension("1.3.6.1.4.1.41482.3.9", [formFactor], false));
    }
}
