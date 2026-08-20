using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Blinky.Pki.BuiltIn;

/// <summary>What has been revoked, and how to publish it.</summary>
public interface ICrlStore
{
    void Revoke(RevocationRequest request, DateTimeOffset when);

    /// <summary>Builds the current list, signed by the issuer.</summary>
    CrlDocument Build(X509Certificate2 issuer, X509SignatureGenerator generator);
}

/// <summary>
/// Revocations held in memory and rebuilt on demand.
/// </summary>
/// <remarks>
/// Enough to make revocation real end to end. Persistence belongs with the
/// worker that regenerates and publishes the list on a schedule — patch 0041 —
/// and putting it here first would have meant writing it twice.
/// </remarks>
public sealed class InMemoryCrlStore(TimeSpan validity) : ICrlStore
{
    private readonly Dictionary<string, (DateTimeOffset When, X509RevocationReason Reason)> revoked
        = new(StringComparer.OrdinalIgnoreCase);

    private readonly Lock gate = new();

    /// <summary>How many certificates this list currently names.</summary>
    public int Count
    {
        get
        {
            lock (gate)
            {
                return revoked.Count;
            }
        }
    }

    public void Revoke(RevocationRequest request, DateTimeOffset when)
    {
        lock (gate)
        {
            // Revoking twice is not an error. An operator retrying after a
            // timeout must not be told the certificate is fine.
            revoked[request.SerialNumber] = (when, request.Reason);
        }
    }

    public bool IsRevoked(string serialNumber)
    {
        lock (gate)
        {
            return revoked.ContainsKey(serialNumber);
        }
    }

    public CrlDocument Build(X509Certificate2 issuer, X509SignatureGenerator generator)
    {
        var thisUpdate = DateTimeOffset.UtcNow;
        var nextUpdate = thisUpdate.Add(validity);

        var builder = new CertificateRevocationListBuilder();

        lock (gate)
        {
            foreach (var (serial, entry) in revoked)
            {
                builder.AddEntry(Convert.FromHexString(serial), entry.When,
                    (System.Security.Cryptography.X509Certificates.X509RevocationReason)entry.Reason);
            }
        }

        var der = builder.Build(issuer.SubjectName, generator, crlNumber: thisUpdate.Ticks,
            nextUpdate, HashAlgorithmName.SHA256,
            authorityKeyIdentifier: X509AuthorityKeyIdentifierExtension
                .CreateFromCertificate(issuer, includeKeyIdentifier: true, includeIssuerAndSerial: false),
            thisUpdate: thisUpdate);

        return new CrlDocument(der, thisUpdate, nextUpdate);
    }
}
