using System.Net.Http.Json;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Blinky.Contracts;
using Microsoft.Win32;

namespace Blinky.AdcsConnector;

/// <summary>
/// The certificate this connector presents to the API, enrolled by the connector itself
/// with a connector enrolment token (0105).
/// </summary>
/// <remarks>
/// <para>
/// Before this a person made a CSR with <c>new-connector-request.ps1</c>, signed it on
/// the Docker host, accepted it here and pasted two fingerprints into two files. The
/// API has taken a connector token since 0102 and nothing on this side spent one.
/// </para>
/// <para>
/// The key is made here, sent nowhere, and put in the store non-exportable, as the
/// agent does: <c>LocalMachine\My</c> when the service may write there, otherwise the
/// service account's own <c>CurrentUser\My</c>, which is where an ordinary domain
/// account running the service ends up. The connector id rides in the friendly name, so
/// <c>certmgr.msc</c> shows which registration in the console a certificate belongs to.
/// </para>
/// <para>
/// The token comes from the registry, where the MSI writes it, or from configuration,
/// and is deleted from the registry once spent: it buys one enrolment and has no
/// business outliving it on the disk of the CA's neighbour.
/// </para>
/// </remarks>
public sealed class ConnectorIdentity(ILogger<ConnectorIdentity> logger)
{
    public const string RegistryKey = @"SOFTWARE\Blinky\AdcsConnector";
    public const string TokenValue = "EnrolmentToken";

    private const string FriendlyNamePrefix = "Blinky ADCS connector ";
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    /// <summary>The newest enrolled certificate with a key this account can use, from either store.</summary>
    public X509Certificate2? Find()
    {
        X509Certificate2? newest = null;

        foreach (var location in new[] { StoreLocation.LocalMachine, StoreLocation.CurrentUser })
        {
            using var store = new X509Store(StoreName.My, location);

            try
            {
                store.Open(OpenFlags.ReadOnly);
            }
            catch (CryptographicException)
            {
                continue;
            }

            foreach (var candidate in Ours(store))
            {
                if (candidate.HasPrivateKey && candidate.NotAfter > DateTime.Now
                    && (newest is null || candidate.NotAfter > newest.NotAfter))
                {
                    newest?.Dispose();
                    newest = candidate;
                }
                else
                {
                    candidate.Dispose();
                }
            }
        }

        return newest;
    }

    /// <summary>The enrolment token the MSI left in the registry, or the one in configuration.</summary>
    public static string? Token(ApiOptions api)
    {
        using var key = Registry.LocalMachine.OpenSubKey(RegistryKey);

        return key?.GetValue(TokenValue) as string is { Length: > 0 } fromRegistry
            ? fromRegistry.Trim()
            : api.EnrolmentToken is { Length: > 0 } configured ? configured.Trim() : null;
    }

    /// <summary>Spends the token: a key, a CSR, the API's certificate, into the store.</summary>
    public async Task<X509Certificate2> EnrolAsync(ApiOptions api, string token, CancellationToken ct)
    {
        var hostname = Environment.MachineName;
        var domain = IPGlobalProperties.GetIPGlobalProperties().DomainName;

        if (string.IsNullOrWhiteSpace(domain))
        {
            throw new InvalidOperationException(
                "This machine has no DNS domain. A connector runs on a domain member, and the token "
                + "may be limited to one domain, which is checked against this.");
        }

        using var key = RSA.Create(3072);
        var request = new CertificateRequest($"CN={hostname}.{domain}", key,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // No client certificate yet, which is what the enrolment route is for. The
        // server is checked exactly as every later poll checks it.
        using var client = ApiPoller.CreateClient(api, certificate: null);

        using var response = await client.PostAsJsonAsync(ConnectorEnrolment.Path,
            new ConnectorEnrolmentRequest(hostname, domain, token, request.CreateSigningRequestPem()), Json, ct);

        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync(ct);

            throw new InvalidOperationException(
                $"The API refused this connector's enrolment: {(int)response.StatusCode} "
                + $"{(body.Length > 300 ? body[..300] : body)}"
                + ((int)response.StatusCode == 401
                    ? " - the token is wrong, spent, expired, withdrawn, made for agents rather than "
                      + $"connectors, or limited to a domain other than {domain}."
                    : string.Empty));
        }

        var answer = await response.Content.ReadFromJsonAsync<ConnectorEnrolmentAnswer>(Json, ct)
                     ?? throw new InvalidOperationException("The API answered the enrolment with no body.");

        var stored = Store(answer, key);
        Forget();

        logger.LogInformation(
            "Enrolled as connector {Id} ({Host}.{Domain}); certificate {Fingerprint} until {NotAfter:yyyy-MM-dd}, "
            + "issued by {Issuer}", answer.ConnectorId, hostname, domain, answer.Fingerprint, answer.NotAfter,
            answer.IssuerSubject);

        return stored;
    }

    private X509Certificate2 Store(ConnectorEnrolmentAnswer answer, RSA key)
    {
        using var signed = X509Certificate2.CreateFromPem(answer.CertificatePem);
        using var withKey = signed.CopyWithPrivateKey(key);

        var (location, store) = Writable();

        using (store)
        {
            // Through PKCS#12 with a throwaway password, because that is the only way to
            // hand a key to the store; without Exportable it cannot be read back out.
            var password = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            var flags = X509KeyStorageFlags.PersistKeySet
                        | (location == StoreLocation.LocalMachine ? X509KeyStorageFlags.MachineKeySet : 0);

            var certificate = X509CertificateLoader.LoadPkcs12(
                withKey.Export(X509ContentType.Pkcs12, password), password, flags);

            certificate.FriendlyName = FriendlyNamePrefix + answer.ConnectorId;

            // The new one in before the old ones out: a crash between the two leaves two
            // working certificates rather than none.
            var previous = Ours(store);
            store.Add(certificate);

            foreach (var stale in previous)
            {
                store.Remove(stale);
                stale.Dispose();
            }

            logger.LogInformation("The connector certificate was written to {Location}\\My", location);

            return certificate;
        }
    }

    private static (StoreLocation, X509Store) Writable()
    {
        try
        {
            var machine = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            machine.Open(OpenFlags.ReadWrite);

            return (StoreLocation.LocalMachine, machine);
        }
        catch (Exception ex) when (ex is CryptographicException or UnauthorizedAccessException)
        {
            var user = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            user.Open(OpenFlags.ReadWrite);

            return (StoreLocation.CurrentUser, user);
        }
    }

    private void Forget()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RegistryKey, writable: true);
            key?.DeleteValue(TokenValue, throwOnMissingValue: false);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            // The token is spent either way; a copy left behind buys nothing more. Said,
            // because somebody reading the registry later deserves to know why it is there.
            logger.LogWarning("The spent enrolment token could not be removed from HKLM\\{Key}: {Message}",
                RegistryKey, ex.Message);
        }
    }

    private static List<X509Certificate2> Ours(X509Store store) =>
        [.. store.Certificates
            .Cast<X509Certificate2>()
            .Where(certificate =>
                certificate.FriendlyName.StartsWith(FriendlyNamePrefix, StringComparison.Ordinal)
                && Guid.TryParse(certificate.FriendlyName[FriendlyNamePrefix.Length..], out _))];
}
