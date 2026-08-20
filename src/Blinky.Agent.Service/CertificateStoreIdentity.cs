using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Blinky.Agent.Service;

/// <summary>
/// The agent's identity in the Windows certificate store.
/// </summary>
/// <remarks>
/// <para>
/// This is where a client certificate belongs on Windows. A private key in a
/// file is a private key somebody can copy: it inherits whatever the directory
/// grants, it survives in backups, and it can be read by anything running as
/// the account that owns it. A key imported here is held by CNG, marked
/// non-exportable, and never handed back as bytes — the most an attacker on the
/// machine can do is use it while they are on the machine, which is a
/// materially smaller thing than walking away with it.
/// </para>
/// <para>
/// <b>LocalMachine, or CurrentUser.</b> A service running as LocalSystem writes
/// to <c>LocalMachine\My</c> — <c>certlm.msc</c>, the machine's own store,
/// which is right: the identity belongs to the workstation, not to whoever
/// happens to be logged in. A bench process running as a person cannot write
/// there without elevation, so it falls back to <c>CurrentUser\My</c> —
/// <c>certmgr.msc</c>. Which one was used is logged, because "it enrolled
/// again" is otherwise a mystery when the same machine is run both ways.
/// </para>
/// <para>
/// The agent id lives in the certificate's friendly name, so there is no second
/// file to keep in step with the first — and an operator opening
/// <c>certlm.msc</c> can see which agent row a certificate belongs to without
/// decoding anything.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class CertificateStoreIdentity(ILogger<CertificateStoreIdentity> logger)
    : IAgentIdentity
{
    /// <summary>
    /// What marks a certificate as ours, and carries the agent id with it.
    /// </summary>
    private const string FriendlyNamePrefix = "Blinky agent ";

    public string Description => $"the {Location()} certificate store";

    public bool Exists => Find() is not null;

    public Guid ReadId()
    {
        using var certificate = Find()
                                ?? throw new InvalidOperationException(
                                    "This machine has no Blinky agent certificate.");

        return Guid.Parse(certificate.FriendlyName[FriendlyNamePrefix.Length..]);
    }

    public X509Certificate2 Load() =>
        Find() ?? throw new InvalidOperationException(
            "This machine has no Blinky agent certificate.");

    public void Store(Guid agentId, string certificatePem, RSA key)
    {
        using var signed = X509Certificate2.CreateFromPem(certificatePem);
        using var withKey = signed.CopyWithPrivateKey(key);

        // Through PKCS#12 because that is the only way to hand a key to the
        // store, and with a throwaway password because the bytes exist for the
        // length of this statement.
        var password = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

        var flags = X509KeyStorageFlags.PersistKeySet;

        if (Location() == StoreLocation.LocalMachine)
        {
            flags |= X509KeyStorageFlags.MachineKeySet;
        }

        // Exportable is deliberately absent. Once this is in the store the key
        // cannot be read back out - not by this agent, not by anything else
        // running as the same account. Recovery is re-enrolment, which costs a
        // round trip and is the correct price.
        var certificate = X509CertificateLoader.LoadPkcs12(
            withKey.Export(X509ContentType.Pkcs12, password), password, flags);

        certificate.FriendlyName = FriendlyNamePrefix + agentId;

        using var store = new X509Store(StoreName.My, Location());
        store.Open(OpenFlags.ReadWrite);

        // The old one goes only after the new one is in. A crash between the
        // two leaves two working certificates, which the next start resolves by
        // taking the later one; the other order leaves none.
        var previous = Ours(store);

        store.Add(certificate);

        foreach (var stale in previous)
        {
            store.Remove(stale);
            stale.Dispose();
        }

        logger.LogInformation("The agent certificate was written to {Store}, valid until "
                              + "{NotAfter:yyyy-MM-dd}", Description, certificate.NotAfter);
    }

    /// <summary>
    /// The newest of ours that has a usable private key.
    /// </summary>
    /// <remarks>
    /// Newest by expiry rather than by issue date: a renewal that overlaps
    /// should win, and a certificate that arrived later with a shorter life is
    /// not the one to authenticate with.
    /// </remarks>
    private X509Certificate2? Find()
    {
        using var store = new X509Store(StoreName.My, Location());

        try
        {
            store.Open(OpenFlags.ReadOnly);
        }
        catch (CryptographicException ex)
        {
            logger.LogWarning("The {Store} could not be opened: {Message}",
                Description, ex.Message);

            return null;
        }

        var candidates = Ours(store)
            .Where(certificate => certificate.HasPrivateKey)
            .OrderByDescending(certificate => certificate.NotAfter)
            .ToList();

        var newest = candidates.FirstOrDefault();

        foreach (var other in candidates.Skip(1))
        {
            other.Dispose();
        }

        return newest;
    }

    private static List<X509Certificate2> Ours(X509Store store) =>
        [.. store.Certificates
            .Cast<X509Certificate2>()
            .Where(certificate =>
                certificate.FriendlyName.StartsWith(FriendlyNamePrefix, StringComparison.Ordinal)
                && Guid.TryParse(certificate.FriendlyName[FriendlyNamePrefix.Length..], out _))];

    /// <summary>
    /// The machine store when it can be written to, otherwise the user's.
    /// </summary>
    /// <remarks>
    /// Asked by trying, because there is no reliable way to predict it: an
    /// administrator's process is not elevated by default, and a service is.
    /// The answer does not change while the process runs.
    /// </remarks>
    private static StoreLocation? location;

    private static StoreLocation Location()
    {
        if (location is { } known)
        {
            return known;
        }

        try
        {
            using var machine = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            machine.Open(OpenFlags.ReadWrite);

            location = StoreLocation.LocalMachine;
        }
        catch (Exception ex) when (ex is CryptographicException or UnauthorizedAccessException)
        {
            location = StoreLocation.CurrentUser;
        }

        return location.Value;
    }
}
