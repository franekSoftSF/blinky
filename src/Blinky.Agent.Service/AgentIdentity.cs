using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Blinky.Agent.Service;

/// <summary>
/// The agent's own identity: its id and the client certificate it
/// authenticates with.
/// </summary>
/// <remarks>
/// <para>
/// Kept for platforms with no certificate store — patch 0017's Linux agent —
/// and for a bench where nobody wants an enrolment writing into the machine
/// store. On Windows the real implementation is
/// <see cref="CertificateStoreIdentity"/>: a private key in a file is a private
/// key somebody can copy.
/// </para>
/// <para>
/// Outside the installation directory and deliberately not removed by an
/// uninstall. A version upgrade must not look like a new agent.
/// </para>
/// </remarks>
public sealed class FileAgentIdentity(string directory) : IAgentIdentity
{
    public string Description => directory;

    private string IdPath => Path.Combine(directory, "agent-id.txt");

    private string CertificatePath => Path.Combine(directory, "agent.crt");

    private string KeyPath => Path.Combine(directory, "agent.key");

    public bool Exists => File.Exists(IdPath) && File.Exists(CertificatePath)
                                              && File.Exists(KeyPath);

    public static FileAgentIdentity Default() => new(Path.Combine(
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
        // Not Directory.CreateDirectory: under %ProgramData% that inherits
        // BUILTIN\\Users:(RX), and the next line writes a private key
        // into it. See AgentPaths.
        if (OperatingSystem.IsWindows())
        {
            AgentPaths.Secure(directory);
        }
        else
        {
            Directory.CreateDirectory(directory);
        }

        File.WriteAllText(IdPath, agentId.ToString());
        File.WriteAllText(CertificatePath, certificatePem);
        File.WriteAllText(KeyPath, key.ExportPkcs8PrivateKeyPem());
    }
}
