using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Blinky.Agent.Service;

/// <summary>
/// The agent's own identity: its id, and the client certificate it
/// authenticates with.
/// </summary>
/// <remarks>
/// <para>
/// Kept outside the installation directory and deliberately not removed by an
/// uninstall. A version upgrade must not look like a new agent — that would
/// split one machine's history across two rows and lose whatever the old one
/// knew.
/// </para>
/// <para>
/// Two implementations, and the Windows one is the real one:
/// <see cref="CertificateStoreIdentity"/> keeps the key where Windows keeps
/// keys, and <see cref="FileAgentIdentity"/> keeps it in a directory for
/// platforms that have no such place — and for a bench where nobody wants to
/// touch the machine store.
/// </para>
/// </remarks>
public interface IAgentIdentity
{
    /// <summary>True when this machine has already enrolled.</summary>
    bool Exists { get; }

    Guid ReadId();

    /// <summary>The certificate, with its private key, ready for TLS.</summary>
    X509Certificate2 Load();

    void Store(Guid agentId, string certificatePem, RSA key);

    /// <summary>Where it lives, for the one log line that says so at startup.</summary>
    string Description { get; }
}
