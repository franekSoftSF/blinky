using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Blinky.Contracts;
using Blinky.Pki.BuiltIn;

namespace Blinky.Pki.Adcs;

/// <summary>
/// Something that holds an enrolment agent key this process cannot touch, and
/// will sign a <c>PKIData</c> with it.
/// </summary>
/// <remarks>
/// Separate from <see cref="IAdcsTransport"/> because CES has no such thing:
/// there is no Blinky service on the far side of a CES call to hold a key. Only
/// the connector implements this.
/// </remarks>
public interface IRemoteEnrolmentAgent
{
    /// <summary>The agent the far side holds, or null when it holds none.</summary>
    Task<AdcsEnrolmentAgentInfo?> DescribeAgentAsync(CancellationToken ct = default);

    /// <summary>DER of a <c>PKIData</c> in, DER of the signed CMS out.</summary>
    Task<byte[]> SignPkiDataAsync(byte[] pkiData, CancellationToken ct = default);
}

/// <summary>
/// The enrolment agent's key on the connector's Windows server, asked for a
/// signature over the wire.
/// </summary>
/// <remarks>
/// <para>
/// The arrangement for any deployment whose transport is the connector. The key
/// stays in the integration account's store beside the CA - non-exportable, or in
/// a TPM - and never exists as a file in the container. What stays here is
/// everything that decides: the <c>PKIData</c> is built by
/// <see cref="CmcRequest"/> on this side, with the cardholder and template chosen
/// here, and the connector only signs it after refusing anything that is not one
/// enrolment. See docs/15-adcs-connector.md and docs/06-security.md.
/// </para>
/// <para>
/// The cost is stated once, because it is easy to lose: the client certificate
/// this process uses to reach the connector is now worth as much as the
/// enrolment agent key, since holding it buys that key's signature.
/// </para>
/// </remarks>
public sealed class ConnectorEnrolmentAgentKeyStore : IEnrolmentAgentKeyStore
{
    private readonly IRemoteEnrolmentAgent remote;
    private readonly X509Certificate2 certificate;

    private ConnectorEnrolmentAgentKeyStore(
        IRemoteEnrolmentAgent remote, X509Certificate2 certificate, string description,
        KeyCustody custody)
    {
        this.remote = remote;
        this.certificate = certificate;
        Description = description;
        Custody = custody;
    }

    public X509Certificate2 Certificate => certificate;

    public string Description { get; }

    public KeyCustody Custody { get; }

    /// <summary>
    /// Asks the connector which enrolment agent it holds and refuses one ADCS
    /// would refuse.
    /// </summary>
    /// <remarks>
    /// The certificate is checked here as well as on the connector. The connector
    /// checks at start and at each signature; this check is what makes a
    /// registration fail with a sentence, which is the earliest anybody can find
    /// out - 0033.
    /// </remarks>
    public static async Task<ConnectorEnrolmentAgentKeyStore> OpenAsync(
        IRemoteEnrolmentAgent remote, string where, DateTimeOffset? now = null,
        CancellationToken ct = default)
    {
        var agent = await remote.DescribeAgentAsync(ct)
            ?? throw new CertificateAuthorityException(
                $"The connector at {where} holds no enrolment agent. Enrol the integration "
                + "account for an Enrollment Agent certificate and set "
                + "Connector:EnrolmentAgent:Thumbprint on that server.");

        X509Certificate2 certificate;
        try
        {
            certificate = X509CertificateLoader.LoadCertificate(
                Convert.FromBase64String(agent.Certificate));
        }
        catch (Exception ex) when (ex is FormatException
                                       or System.Security.Cryptography.CryptographicException)
        {
            throw new CertificateAuthorityException(
                $"The enrolment agent certificate the connector at {where} reported could not be "
                + "read: " + ex.Message, ex);
        }

        FileEnrolmentAgentKeyStore.RequireAgentCertificate(
            certificate, $"the connector at {where}", now ?? DateTimeOffset.UtcNow);

        return new ConnectorEnrolmentAgentKeyStore(
            remote, certificate, $"connector at {where}, {agent.Source}", CustodyOf(agent));
    }

    public async Task<byte[]> SignCmsAsync(ContentInfo content, CancellationToken ct = default)
    {
        // Refused here as well as there. The connector signs PKIData and nothing
        // else, and asking it for anything else would be a round trip to be told
        // so.
        if (content.ContentType.Value != CmcRequest.PkiDataContentType)
        {
            throw new CertificateAuthorityException(
                $"The connector's enrolment agent signs PKIData ({CmcRequest.PkiDataContentType}) "
                + $"and nothing else, and was asked to sign {content.ContentType.Value}.");
        }

        return await remote.SignPkiDataAsync(content.Content, ct);
    }

    /// <summary>
    /// Custody from what the connector read off the key, not from where it is.
    /// </summary>
    /// <remarks>
    /// Production-ready only when the key says it cannot be exported. Whether it
    /// can was decided by the flag it was imported with, so being on the Windows
    /// server settles nothing, and reporting it as if it did would be the claim
    /// this project already refuses to make about SoftHSM.
    /// </remarks>
    public static KeyCustody CustodyOf(AdcsEnrolmentAgentInfo agent)
    {
        var provider = agent.Provider ?? "a provider that did not name itself";

        if (agent.Source.StartsWith("file:", StringComparison.OrdinalIgnoreCase))
        {
            return new KeyCustody(
                KeyCustodyTier.File,
                agent.Source,
                ProductionReady: false,
                "The enrolment agent's key is a PKCS#12 on the connector's server, and the "
                + "password that opens it is in that server's configuration. Correct for a "
                + "laboratory. It belongs in the integration account's store.");
        }

        return agent.Exportable switch
        {
            false => new KeyCustody(
                KeyCustodyTier.WindowsKeyStore,
                $"{agent.Source}, {provider}",
                ProductionReady: true,
                "The enrolment agent's key is in a Windows store on the connector's server and "
                + "its own export policy forbids it to leave. Whoever holds this deployment's "
                + "client certificate for that connector can still ask it for signatures, so "
                + "that certificate is worth as much as the key."),

            true => new KeyCustody(
                KeyCustodyTier.WindowsKeyStore,
                $"{agent.Source}, {provider}",
                ProductionReady: false,
                "The enrolment agent's key is in a Windows store on the connector's server, and "
                + "it was imported as exportable. Anybody with administrative access to that "
                + "server can take it away. Re-import it without marking the key exportable."),

            null => new KeyCustody(
                KeyCustodyTier.WindowsKeyStore,
                $"{agent.Source}, {provider}",
                ProductionReady: false,
                "The enrolment agent's key is in a Windows store on the connector's server, and "
                + "its provider would not say whether it can be exported. Unknown is not "
                + "reported as safe."),
        };
    }

    public void Dispose() => certificate.Dispose();
}
