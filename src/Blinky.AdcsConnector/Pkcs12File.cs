using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Blinky.AdcsConnector;

/// <summary>
/// A PKCS#12 from a file, in a session that may not be able to protect a key for
/// its own user.
/// </summary>
/// <remarks>
/// <para>
/// Importing a PFX into the user's key set asks DPAPI to protect the private key
/// with that user's master key, and DPAPI can only do that when the logon carried
/// the user's credential. A service started by the service control manager has it.
/// A key-authenticated SSH session does not, and neither does a scheduled task set
/// to run without storing a password. Measured on HZCS01, a domain member running
/// Windows Server 2022, over OpenSSH with a key: the default and user key sets
/// failed with "Access denied", while the machine and ephemeral key sets loaded
/// the same file. The connector died on its first start there.
/// </para>
/// <para>
/// So the user key set first, because it is right for the integration account the
/// connector is meant to run as, and the machine key set when that is refused. Not
/// the ephemeral key set, although it loaded too: Schannel will not serve TLS from
/// a key that was never persisted, and the listener is the file this is mostly for.
/// </para>
/// <para>
/// Which one was used is reported, because the machine key set persists the key
/// under <c>%ProgramData%\Microsoft\Crypto</c> for as long as the process holds it,
/// readable by the machine's administrators - and a store-held certificate by
/// fingerprint, which is the production arrangement, needs none of this.
/// </para>
/// </remarks>
public static class Pkcs12File
{
    public static X509Certificate2 Load(string path, string? password, out string keySet)
    {
        try
        {
            keySet = "user";

            return X509CertificateLoader.LoadPkcs12FromFile(
                path, password, X509KeyStorageFlags.UserKeySet);
        }
        catch (CryptographicException asUser)
        {
            keySet = "machine - this session could not protect a key for its own user";

            try
            {
                return X509CertificateLoader.LoadPkcs12FromFile(
                    path, password, X509KeyStorageFlags.MachineKeySet);
            }
            catch (CryptographicException asMachine)
            {
                // Both refused. A wrong password fails both the same way; an
                // account that is neither credentialed nor an administrator fails
                // each for its own reason, and both reasons are worth reading.
                throw new InvalidOperationException(
                    $"{path} could not be opened. As this user: {asUser.Message} As the machine: "
                    + $"{asMachine.Message} A wrong password gives the same answer twice.",
                    asMachine);
            }
        }
    }
}
