using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Blinky.AdcsConnector;

namespace Blinky.UnitTests;

/// <summary>
/// Who the connector will talk to. This is the whole of its access control:
/// the handshake accepts any client certificate on purpose, so a mistake here
/// is a Microsoft CA taking enrolment requests from strangers.
/// </summary>
public sealed class AdcsConnectorGateTests
{
    private static X509Certificate2 Caller(
        string name = "CN=blinky-api", int notBeforeDays = -1, int notAfterDays = 30)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var request = new CertificateRequest(name, key, HashAlgorithmName.SHA256);

        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(notBeforeDays), DateTimeOffset.UtcNow.AddDays(notAfterDays));
    }

    [Fact]
    public void The_listed_caller_is_allowed()
    {
        using var caller = Caller();
        var gate = new ClientCertificateGate([ClientCertificateGate.FingerprintOf(caller)]);

        Assert.True(gate.Allows(caller, TimeProvider.System, out _));
    }

    [Fact]
    public void An_unlisted_caller_is_refused_with_a_reason()
    {
        using var listed = Caller();
        using var stranger = Caller("CN=somebody-else");

        var gate = new ClientCertificateGate([ClientCertificateGate.FingerprintOf(listed)]);

        Assert.False(gate.Allows(stranger, TimeProvider.System, out var reason));
        Assert.Contains("not one this connector", reason, StringComparison.Ordinal);
    }

    [Fact]
    public void No_certificate_at_all_is_refused()
    {
        using var listed = Caller();
        var gate = new ClientCertificateGate([ClientCertificateGate.FingerprintOf(listed)]);

        Assert.False(gate.Allows(null, TimeProvider.System, out var reason));
        Assert.Contains("No client certificate", reason, StringComparison.Ordinal);
    }

    [Fact]
    public void An_expired_caller_is_refused_even_though_its_fingerprint_is_listed()
    {
        // Nothing else checks the dates. The handshake was told to accept any
        // certificate, so without this an expired client certificate whose
        // fingerprint is still in the file would keep working for years.
        using var expired = Caller(notBeforeDays: -400, notAfterDays: -30);

        var gate = new ClientCertificateGate([ClientCertificateGate.FingerprintOf(expired)]);

        Assert.False(gate.Allows(expired, TimeProvider.System, out var reason));
        Assert.Contains("validity period", reason, StringComparison.Ordinal);
    }

    [Theory]
    // certutil, lower case with spaces; the Windows certificate dialog, spaced
    // pairs; openssl, colon separated. Each of these is how somebody actually
    // obtains the value they paste into the configuration file.
    [InlineData("ab cd ef 01", "ABCDEF01")]
    [InlineData("AB:CD:EF:01", "ABCDEF01")]
    [InlineData("  abcdef01\n", "ABCDEF01")]
    public void A_fingerprint_is_read_however_it_was_copied(string written, string expected) =>
        Assert.Equal(expected, ClientCertificateGate.Normalise(written));

    [Fact]
    public void Nothing_configured_is_not_the_same_as_everybody_allowed()
    {
        var gate = new ClientCertificateGate([]);

        Assert.True(gate.IsEmpty);

        using var caller = Caller();
        Assert.False(gate.Allows(caller, TimeProvider.System, out _));
    }

    [Fact]
    public void The_fingerprint_is_sha256_rather_than_the_sha1_thumbprint_property()
    {
        using var caller = Caller();

        // 32 bytes as hex. X509Certificate2.Thumbprint would be 40 characters,
        // and a SHA-1 fingerprint is not a thing to write a security decision
        // down in.
        Assert.Equal(64, ClientCertificateGate.FingerprintOf(caller).Length);
        Assert.NotEqual(caller.Thumbprint, ClientCertificateGate.FingerprintOf(caller));
    }
}
