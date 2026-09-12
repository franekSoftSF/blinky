using System.Net;
using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Blinky.Contracts;

namespace Blinky.Pki.Adcs;

/// <summary>
/// The connector, over HTTPS, from the container. The other half of patch 0032.
/// </summary>
/// <remarks>
/// <para>
/// Speaks the contract in <c>Blinky.Contracts/AdcsTransportContracts.cs</c> and
/// nothing else. What crosses this wire is a CMC already signed by the enrolment
/// agent, so the two things that matter here are that the far end is the
/// connector it claims to be, and that a version mismatch is refused rather than
/// guessed at. See docs/15-adcs-connector.md.
/// </para>
/// <para>
/// There is no "accept any server certificate" option, unlike
/// <c>BackendClient</c> where one exists for a single-machine bench. A CMC
/// signed by the enrolment agent is worth having: whoever intercepts one can
/// submit it to the real CA and collect a certificate in the cardholder's name.
/// An unauthenticated server here is not a relaxed check, it is a way to hand
/// that request to a stranger, so the transport refuses to be built without
/// either a pinned fingerprint or a trust anchor.
/// </para>
/// </remarks>
public sealed class ConnectorAdcsTransport : IAdcsTransport, IRemoteEnrolmentAgent, IDisposable
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    private readonly ConnectorTransportOptions options;
    private readonly HttpClient client;
    private readonly X509Certificate2? identity;
    private readonly X509Certificate2Collection anchors = [];
    private readonly string? pinned;

    public ConnectorAdcsTransport(ConnectorTransportOptions options)
    {
        this.options = options;

        if (options.ClientCertificatePath is not { Length: > 0 } path)
        {
            throw new CertificateAuthorityException(
                "The connector requires a client certificate and none is configured. Its "
                + "fingerprint is what the connector was told to accept; without it every call "
                + "is refused with a 403 that names nothing.");
        }

        pinned = Normalise(options.ServerFingerprint);

        if (pinned is null && options.ServerCertificateAuthorityPath is { Length: > 0 } anchor)
        {
            anchors.Add(LoadAnchor(anchor));
        }

        if (pinned is null && anchors.Count == 0)
        {
            throw new CertificateAuthorityException(
                "The connector's server certificate is neither pinned by fingerprint nor "
                + "anchored to a CA. Blinky will not send an enrolment agent's signature to a "
                + "server it cannot identify.");
        }

        identity = X509CertificateLoader.LoadPkcs12FromFile(
            path, options.ClientCertificatePassword);

        if (!identity.HasPrivateKey)
        {
            throw new CertificateAuthorityException(
                $"{path} holds a certificate but no private key, so it cannot authenticate to "
                + "the connector.");
        }

        client = new HttpClient(Handler())
        {
            BaseAddress = options.BaseAddress,
            Timeout = TimeSpan.FromSeconds(Math.Max(10, options.TimeoutSeconds)),
        };

        client.DefaultRequestHeaders.Add(
            AdcsTransport.SchemaHeader, AdcsTransport.SchemaVersion.ToString());
    }

    /// <summary>For tests: the same client against a handler that is not a socket.</summary>
    internal ConnectorAdcsTransport(ConnectorTransportOptions options, HttpMessageHandler handler)
    {
        this.options = options;

        client = new HttpClient(handler) { BaseAddress = options.BaseAddress };
        client.DefaultRequestHeaders.Add(
            AdcsTransport.SchemaHeader, AdcsTransport.SchemaVersion.ToString());
    }

    public string Description => $"connector at {options.BaseAddress}";

    public async Task<AdcsDescribeResponse> DescribeAsync(CancellationToken ct = default)
    {
        var query = options.CaConfig is { Length: > 0 } config
            ? "/connector/describe?caConfig=" + Uri.EscapeDataString(config)
            : "/connector/describe";

        var described = await ReadAsync<AdcsDescribeResponse>(
            await Send(() => client.GetAsync(query, ct)), ct);

        // Refused here rather than at the first enrolment. The connector is
        // upgraded by whoever owns the CA server, so this is the one mismatch
        // nothing in this repository can fix on its own.
        if (!AdcsTransport.IsSupported(described.SchemaVersion))
        {
            throw new CertificateAuthorityException(
                $"The connector at {options.BaseAddress} speaks schema "
                + $"{described.SchemaVersion} and this build understands "
                + $"{AdcsTransport.MinimumSupportedVersion} to "
                + $"{AdcsTransport.MaximumSupportedVersion}. Its version is "
                + $"{described.ConnectorVersion}.");
        }

        return described;
    }

    public async Task<AdcsSubmitResponse> SubmitAsync(
        byte[] request, AdcsRequestFormat format, string? attributes,
        CancellationToken ct = default)
    {
        var body = new AdcsSubmitRequest(
            AdcsTransport.SchemaVersion,
            Convert.ToBase64String(request),
            format,
            attributes,
            options.CaConfig);

        return await PostAsync<AdcsSubmitRequest, AdcsSubmitResponse>("/connector/submit", body, ct);
    }

    public async Task<AdcsSubmitResponse> RetrieveAsync(
        int requestId, CancellationToken ct = default)
    {
        var body = new AdcsRetrieveRequest(
            AdcsTransport.SchemaVersion, requestId, options.CaConfig);

        return await PostAsync<AdcsRetrieveRequest, AdcsSubmitResponse>(
            "/connector/retrieve", body, ct);
    }

    public async Task<AdcsRevokeResponse> RevokeAsync(
        string serialNumber, int reason, DateTimeOffset? effectiveAt,
        CancellationToken ct = default)
    {
        var body = new AdcsRevokeRequest(
            AdcsTransport.SchemaVersion, serialNumber, reason, effectiveAt, options.CaConfig);

        return await PostAsync<AdcsRevokeRequest, AdcsRevokeResponse>(
            "/connector/revoke", body, ct);
    }

    public async Task<AdcsEnrolmentAgentInfo?> DescribeAgentAsync(CancellationToken ct = default) =>
        (await DescribeAsync(ct)).EnrolmentAgent;

    public async Task<byte[]> SignPkiDataAsync(byte[] pkiData, CancellationToken ct = default)
    {
        var answer = await PostAsync<AdcsSignRequest, AdcsSignResponse>(
            "/connector/sign",
            new AdcsSignRequest(AdcsTransport.SchemaVersion, Convert.ToBase64String(pkiData)),
            ct);

        try
        {
            return Convert.FromBase64String(answer.SignedData);
        }
        catch (FormatException ex)
        {
            throw new CertificateAuthorityException(
                $"The connector at {options.BaseAddress} returned a signature that is not base64.",
                ex);
        }
    }

    private async Task<TAnswer> PostAsync<TBody, TAnswer>(
        string path, TBody body, CancellationToken ct)
    {
        var response = await Send(() => client.PostAsJsonAsync(path, body, Json, ct));

        return await ReadAsync<TAnswer>(response, ct);
    }

    /// <summary>
    /// Turns the ways a network call fails into one exception type with a reason
    /// somebody can act on.
    /// </summary>
    /// <remarks>
    /// A timeout arrives as an <see cref="OperationCanceledException"/> and looks
    /// identical to a shutdown, which is how "the CA is not answering" gets
    /// logged as "the request was cancelled" and costs an afternoon.
    /// </remarks>
    private async Task<HttpResponseMessage> Send(Func<Task<HttpResponseMessage>> call)
    {
        try
        {
            return await call();
        }
        catch (HttpRequestException ex)
        {
            throw new CertificateAuthorityException(
                $"The connector at {options.BaseAddress} could not be reached: {ex.Message}. "
                + "A TLS failure here is usually the pinned fingerprint or the anchor, and a "
                + "refused connection is usually the firewall rule for its port.", ex);
        }
        catch (TaskCanceledException ex)
        {
            throw new CertificateAuthorityException(
                $"The connector at {options.BaseAddress} did not answer within "
                + $"{client.Timeout.TotalSeconds}s. It serialises calls into the CA, so a "
                + "submission that overran leaves it busy until the CA answers.", ex);
        }
    }

    private async Task<T> ReadAsync<T>(HttpResponseMessage response, CancellationToken ct)
    {
        if (response.IsSuccessStatusCode)
        {
            // Wrapped, because an empty body does not come back as null: a 204,
            // or a proxy that answered 200 with nothing in it, throws out of the
            // reader. Letting that through means a JSON exception where a
            // sentence about the connector belongs.
            try
            {
                return await response.Content.ReadFromJsonAsync<T>(Json, ct)
                    ?? throw new CertificateAuthorityException(Empty(response));
            }
            catch (Exception ex) when (ex is JsonException or NotSupportedException)
            {
                throw new CertificateAuthorityException(Empty(response), ex);
            }
        }

        var problem = await Problem(response, ct);

        // Named separately because it is the predictable deployment failure and
        // it is not a fault at the CA. The connector authorises by fingerprint,
        // so a 403 means this client certificate is not in its list - often
        // because it was rotated here and not there.
        if (response.StatusCode == HttpStatusCode.Forbidden)
        {
            throw new CertificateAuthorityException(
                $"The connector at {options.BaseAddress} refused this client certificate: "
                + problem + " Add its SHA-256 fingerprint to "
                + "Connector:AllowedClientThumbprints on the CA server.");
        }

        throw new CertificateAuthorityException(
            $"The connector at {options.BaseAddress} answered {(int)response.StatusCode}: "
            + problem);
    }

    private string Empty(HttpResponseMessage response) =>
        $"The connector at {options.BaseAddress} answered {(int)response.StatusCode} with an "
        + "empty or unreadable body. Something between here and the CA server answered instead "
        + "of the connector.";

    /// <summary>
    /// The connector's own reason, or the status line when it did not give one.
    /// </summary>
    private static async Task<string> Problem(HttpResponseMessage response, CancellationToken ct)
    {
        try
        {
            var problem = await response.Content.ReadFromJsonAsync<AdcsProblem>(Json, ct);

            if (problem?.Reason is { Length: > 0 } reason)
            {
                return problem.Detail is { Length: > 0 } detail
                    ? $"{reason} ({detail})"
                    : reason;
            }
        }
        catch (Exception ex) when (ex is JsonException or NotSupportedException or HttpRequestException)
        {
            // A proxy or a WAF in between answers in HTML. Falling through to
            // the status line is more useful than an exception about JSON.
        }

        return response.ReasonPhrase ?? "no reason given";
    }

    private HttpClientHandler Handler()
    {
        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = Validate,
        };

        if (identity is not null)
        {
            handler.ClientCertificates.Add(identity);
        }

        // Named explicitly: the default would let the platform pick one, and
        // this connection is worth refusing rather than downgrading.
        handler.SslProtocols = System.Security.Authentication.SslProtocols.Tls12
            | System.Security.Authentication.SslProtocols.Tls13;

        return handler;
    }

    private bool Validate(
        HttpRequestMessage request, X509Certificate2? certificate, X509Chain? chain,
        SslPolicyErrors errors)
    {
        if (certificate is null)
        {
            return false;
        }

        if (pinned is not null)
        {
            // A fingerprint and nothing else: no chain, no name, no dates. The
            // connector's certificate is routinely self-signed on a CA server
            // that is not in the PKI it runs, and a pinned fingerprint is a
            // stronger statement than a chain to a CA that signs many things.
            return string.Equals(
                certificate.GetCertHashString(HashAlgorithmName.SHA256),
                pinned,
                StringComparison.Ordinal);
        }

        if (errors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch))
        {
            return false;
        }

        using var built = new X509Chain();
        built.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        built.ChainPolicy.CustomTrustStore.AddRange(anchors);
        built.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

        return built.Build(certificate);
    }

    /// <summary>Upper case hex, separators removed. Same reading as the connector's.</summary>
    private static string? Normalise(string? fingerprint)
    {
        if (fingerprint is null)
        {
            return null;
        }

        var hex = string.Concat(fingerprint.Where(char.IsAsciiHexDigit)).ToUpperInvariant();

        // 32 bytes. A 40-character value is a SHA-1 thumbprint copied out of the
        // wrong field, and silently accepting it would mean pinning nothing.
        if (hex.Length != 64)
        {
            throw new CertificateAuthorityException(
                "Blinky:Adcs:Connector:ServerFingerprint is not a SHA-256 fingerprint: "
                + $"{hex.Length} hex digits rather than 64. A 40-digit value is the SHA-1 "
                + "thumbprint, which is a different field.");
        }

        return hex;
    }

    /// <remarks>
    /// DER and PEM both, for the reason <c>BackendClient.LoadAnchor</c> records:
    /// a <c>.crt</c> is either one depending on which tool produced it, and
    /// reading only PEM meant a valid anchor stopped a service from starting.
    /// </remarks>
    private static X509Certificate2 LoadAnchor(string path)
    {
        if (!File.Exists(path))
        {
            throw new CertificateAuthorityException(
                $"The connector's trust anchor {path} does not exist.");
        }

        var bytes = File.ReadAllBytes(path);

        var looksLikePem = bytes.Length > 10
            && System.Text.Encoding.ASCII.GetString(bytes, 0, 11) == "-----BEGIN ";

        return looksLikePem
            ? X509Certificate2.CreateFromPem(System.Text.Encoding.UTF8.GetString(bytes))
            : X509CertificateLoader.LoadCertificate(bytes);
    }

    public void Dispose()
    {
        client.Dispose();
        identity?.Dispose();
    }
}

/// <summary>
/// How to reach a connector. The secrets are paths and fingerprints, never
/// material.
/// </summary>
/// <param name="ServerFingerprint">
/// SHA-256 of the connector's TLS certificate, any separators. Preferred over an
/// anchor, and symmetric with how the connector authorises this client.
/// </param>
/// <param name="ServerCertificateAuthorityPath">
/// A trust anchor instead, for an estate whose CA server holds a certificate from
/// its own PKI. One of the two is required.
/// </param>
/// <param name="CaConfig">
/// <c>HOST\CA common name</c>, when the connector's own default is not the CA
/// this instance means. Normally unset.
/// </param>
public sealed record ConnectorTransportOptions(
    Uri BaseAddress,
    string? ClientCertificatePath = null,
    string? ClientCertificatePassword = null,
    string? ServerFingerprint = null,
    string? ServerCertificateAuthorityPath = null,
    string? CaConfig = null,
    int TimeoutSeconds = 90);
