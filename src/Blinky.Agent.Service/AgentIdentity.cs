using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Blinky.Agent.Service;

/// <summary>
/// The agent's own identity: its id and the client certificate it
/// authenticates with.
/// </summary>
/// <remarks>
/// Stored outside the installation directory, in ProgramData, and deliberately
/// not removed by uninstall. A version upgrade must not look like a new agent -
/// that would split one machine's history across two rows and lose whatever
/// the old one knew.
/// </remarks>
public sealed class AgentIdentity(string directory)
{
    private string IdPath => Path.Combine(directory, "agent-id.txt");

    private string CertificatePath => Path.Combine(directory, "agent.crt");

    private string KeyPath => Path.Combine(directory, "agent.key");

    public bool Exists => File.Exists(IdPath) && File.Exists(CertificatePath)
                                              && File.Exists(KeyPath);

    public static AgentIdentity Default() => new(Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Blinky"));

    public Guid ReadId() => Guid.Parse(File.ReadAllText(IdPath).Trim());

    public X509Certificate2 Load()
    {
        var certificate = X509Certificate2.CreateFromPemFile(CertificatePath, KeyPath);

        // On Windows a certificate built from PEM cannot be used for TLS client
        // authentication until it has been through a PKCS#12 round trip - the
        // private key is otherwise not associated in a way Schannel accepts.
        return X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pkcs12), null);
    }

    public void Store(Guid agentId, string certificatePem, RSA key)
    {
        Directory.CreateDirectory(directory);

        File.WriteAllText(IdPath, agentId.ToString());
        File.WriteAllText(CertificatePath, certificatePem);
        File.WriteAllText(KeyPath, key.ExportPkcs8PrivateKeyPem());
    }
}
