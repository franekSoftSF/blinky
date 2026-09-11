using System.Text;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

namespace Blinky.Secrets;

/// <summary>
/// The secrets inside a PKCS#11 token, used without ever being read.
/// </summary>
/// <remarks>
/// <para>
/// Nothing here knows which device answered. SoftHSM2 is the first thing this
/// was run against because it is the one every developer can have, but it is
/// reached the same way a YubiHSM is: a module path, a token label, a PIN and
/// a key label. If a line in this file would have to change to support a second
/// device, it is the wrong line.
/// </para>
/// <para>
/// One session, guarded by a lock, reopened when the device drops it. A pool
/// would be faster and is not warranted: these operations happen once per
/// enrolment and once per unblock, and a pool of logged-in sessions is a pool
/// of things that can each be left in a different state after a device is
/// unplugged.
/// </para>
/// </remarks>
public sealed class Pkcs11KeyProvider : IKeyProvider
{
    private readonly Pkcs11InteropFactories factories = new();
    private readonly Pkcs11KeyProviderOptions options;
    private readonly byte[] pin;
    private readonly Lock gate = new();
    private readonly Dictionary<KeyRef, KeyDescription> found = [];

    private IPkcs11Library? library;
    private ISession? session;
    private Dictionary<KeyRef, IObjectHandle> handles = [];
    private bool disposed;

    /// <summary>
    /// Loads the module, finds the token, logs in and checks that the keys this
    /// deployment expects are there and cannot leave.
    /// </summary>
    /// <remarks>
    /// All of it at construction, so that a device which is unreachable or a
    /// token which was never provisioned is a startup failure with a sentence,
    /// rather than a five hundred in the middle of somebody's enrolment.
    /// </remarks>
    public Pkcs11KeyProvider(Pkcs11KeyProviderOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        this.options = options;

        if (string.IsNullOrWhiteSpace(options.Module))
        {
            throw new KeyUnavailableException(
                "No PKCS#11 module is configured. Set Blinky:Secrets:Pkcs11:Module to the "
                + "module the device ships, for example /usr/lib/softhsm/libsofthsm2.so.");
        }

        if (!File.Exists(options.Module))
        {
            throw new KeyUnavailableException(
                $"The PKCS#11 module {options.Module} does not exist. It is a file this "
                + "container has to hold, not a service it can reach.");
        }

        NativeLoader.Prepare();

        pin = ReadPin(options);

        try
        {
            library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(
                factories, options.Module, AppType.MultiThreaded);
        }
        catch (Pkcs11Exception e)
        {
            throw new KeyUnavailableException(
                $"The PKCS#11 module {options.Module} did not load: {e.Message}", e);
        }

        Open();
        Discover();
    }

    public string Name => "pkcs11";

    public KeyCustody Custody { get; private set; } = new(
        Tier: "Pkcs11",
        Description: "a PKCS#11 token",
        ProductionReady: true,
        "The master secrets are held by a token and used without being read.");

    public IReadOnlyCollection<KeyDescription> Keys
    {
        get
        {
            lock (gate)
            {
                return found.Values.ToList();
            }
        }
    }

    public bool Has(KeyRef key)
    {
        lock (gate)
        {
            return handles.ContainsKey(key);
        }
    }

    public byte[] Mac(KeyRef key, ReadOnlySpan<byte> data)
    {
        // Copied out of the span because the retry below crosses a call that
        // may reopen the session, and a span cannot survive that.
        var message = data.ToArray();

        lock (gate)
        {
            ObjectDisposedException.ThrowIf(disposed, this);

            try
            {
                return Sign(key, message);
            }
            catch (Pkcs11Exception e) when (Recoverable(e))
            {
                // A device that was unplugged, a session the module dropped, or
                // a login that expired. Each presents as a different return
                // value and none is worth its own code path: reconnect once,
                // and a second failure is a real fault the caller should hear.
                Reopen();

                return Sign(key, message);
            }
            catch (Pkcs11Exception e)
            {
                throw new KeyUnavailableException(
                    $"The token refused to use {key.Label}: {e.Message}", e);
            }
        }
    }

    public void Dispose()
    {
        lock (gate)
        {
            if (disposed)
            {
                return;
            }

            disposed = true;

            Close();

            library?.Dispose();
            library = null;

            Array.Clear(pin);
        }
    }

    private static byte[] ReadPin(Pkcs11KeyProviderOptions options)
    {
        if (!string.IsNullOrEmpty(options.PinFile))
        {
            if (!File.Exists(options.PinFile))
            {
                throw new KeyUnavailableException(
                    $"The PIN file {options.PinFile} does not exist.");
            }

            // Trimmed, because a PIN written by a shell redirect ends with a
            // newline, and a token told to log in with one counts a wrong PIN.
            // Three of those locks most devices.
            return Encoding.UTF8.GetBytes(File.ReadAllText(options.PinFile).Trim());
        }

        if (!string.IsNullOrEmpty(options.Pin))
        {
            return Encoding.UTF8.GetBytes(options.Pin);
        }

        throw new KeyUnavailableException(
            "No PKCS#11 PIN is configured. Set Blinky:Secrets:Pkcs11:PinFile to a file only "
            + "this process can read.");
    }

    private static bool Recoverable(Pkcs11Exception e) => e.RV
        is CKR.CKR_SESSION_HANDLE_INVALID
        or CKR.CKR_SESSION_CLOSED
        or CKR.CKR_USER_NOT_LOGGED_IN
        or CKR.CKR_DEVICE_REMOVED
        or CKR.CKR_DEVICE_ERROR
        or CKR.CKR_OBJECT_HANDLE_INVALID;

    private static string Present(IEnumerable<ISlot> slots)
    {
        var labels = slots
            .Select(s => string.Concat("\"", s.GetTokenInfo().Label.Trim(), "\""))
            .ToList();

        return labels.Count == 0 ? "no tokens at all" : string.Join(", ", labels);
    }

    private void Open()
    {
        var slots = library!.GetSlotList(SlotsType.WithTokenPresent);

        var slot = slots.FirstOrDefault(s =>
            string.Equals(s.GetTokenInfo().Label.Trim(), options.TokenLabel,
                StringComparison.Ordinal))
            ?? throw new KeyUnavailableException(
                $"No token labelled {options.TokenLabel} is present in {options.Module}. "
                + $"Present: {Present(slots)}. Provision one with scripts/new-secret-keys.sh.");

        session = slot.OpenSession(SessionType.ReadOnly);

        try
        {
            session.Login(CKU.CKU_USER, pin);
        }
        catch (Pkcs11Exception e) when (e.RV == CKR.CKR_USER_ALREADY_LOGGED_IN)
        {
            // Login state belongs to the application rather than to the
            // session, so a second session in the same process is already
            // logged in. Not a fault, and not worth failing a start over.
        }
        catch (Pkcs11Exception e)
        {
            throw new KeyUnavailableException(
                $"The token {options.TokenLabel} refused the PIN: {e.Message}. Two more wrong "
                + "attempts locks most devices.", e);
        }
    }

    private void Close()
    {
        if (session is null)
        {
            return;
        }

        try
        {
            session.Logout();
        }
        catch (Pkcs11Exception)
        {
            // Logging out of a session the device has already forgotten is not
            // worth propagating out of a dispose.
        }

        session.Dispose();
        session = null;
        handles = [];
    }

    private void Reopen()
    {
        Close();
        Open();
        Discover();
    }

    /// <summary>
    /// Finds the keys this deployment is configured to use, and refuses any the
    /// device would hand out.
    /// </summary>
    private void Discover()
    {
        // Every generation up to the configured one, not just the configured
        // one. Rotation only works if it can overlap: a card personalised under
        // version one has to stay manageable while version two is what new
        // cards get, and an envelope written under version two has to stay
        // readable after version three starts being written. A provider that
        // held only the newest key would make each rotation a flag day.
        var wanted =
            Enumerable.Range(1, Math.Max(options.ManagementKeyVersion, 0))
                .Select(v => new KeyRef(KeyPurpose.ManagementKeyMaster, v))
            .Concat(
                Enumerable.Range(PukKekVersions.FirstProviderVersion,
                        Math.Max(options.PukKekVersion - PukKekVersions.Legacy, 0))
                    .Select(v => new KeyRef(KeyPurpose.PukKek, v)))
            .ToList();

        var resolved = new Dictionary<KeyRef, IObjectHandle>();
        var descriptions = new Dictionary<KeyRef, KeyDescription>();

        foreach (var key in wanted)
        {
            var search = new List<IObjectAttribute>
            {
                factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
                factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, key.Label),
            };

            var matches = session!.FindAllObjects(search);

            if (matches.Count == 0)
            {
                // Absent rather than fatal. A deployment may hold one of these
                // and not the other while this is rolled out, and
                // docs/06-security.md calls a missing management-key master a
                // supported state rather than a misconfiguration.
                continue;
            }

            if (matches.Count > 1)
            {
                throw new KeyUnavailableException(
                    $"The token holds {matches.Count} objects labelled {key.Label}. Which one "
                    + "signs is then whichever the module returns first, and that is not a "
                    + "thing to leave to chance for a key every card depends on.");
            }

            resolved[key] = matches[0];
            descriptions[key] = new KeyDescription(key, key.Label, CheckCustody(key, matches[0]));
        }

        handles = resolved;

        found.Clear();

        foreach (var (key, description) in descriptions)
        {
            found[key] = description;
        }

        Custody = Describe(descriptions.Values);
    }

    /// <summary>
    /// Asks the device whether the key can leave it, and believes the answer.
    /// </summary>
    private bool CheckCustody(KeyRef key, IObjectHandle handle)
    {
        bool extractable;
        bool sensitive;

        try
        {
            var attributes = session!.GetAttributeValue(handle,
                [CKA.CKA_EXTRACTABLE, CKA.CKA_SENSITIVE]);

            extractable = attributes[0].GetValueAsBool();
            sensitive = attributes[1].GetValueAsBool();
        }
        catch (Pkcs11Exception e)
        {
            // A module that will not answer is not a module answering no, and
            // treating it as one would put a reassuring word on a status page
            // that nothing had checked.
            if (options.RequireNonExportable)
            {
                throw new KeyUnavailableException(
                    $"The token would not say whether {key.Label} can be extracted, and this "
                    + "deployment requires keys that cannot be. Set "
                    + "Blinky:Secrets:Pkcs11:RequireNonExportable to false to accept that, "
                    + "deliberately.", e);
            }

            return false;
        }

        if (!extractable && sensitive)
        {
            return true;
        }

        if (options.RequireNonExportable)
        {
            throw new KeyUnavailableException(
                $"{key.Label} is marked extractable by the token, so it can be read out of it. "
                + "That is the interface of a device with the custody of a file. Regenerate it "
                + "with scripts/new-secret-keys.sh, or set "
                + "Blinky:Secrets:Pkcs11:RequireNonExportable to false, deliberately.");
        }

        return false;
    }

    private KeyCustody Describe(IEnumerable<KeyDescription> keys)
    {
        var all = keys.ToList();
        var everythingSealed = all.Count > 0 && all.TrueForAll(k => k.NonExportable);
        var where = $"PKCS#11 token {options.TokenLabel} via {options.Module}";

        return everythingSealed
            ? new KeyCustody(
                Tier: "Pkcs11",
                Description: where,
                ProductionReady: true,
                "The master secrets are held by a token that reports them as neither readable "
                + "nor extractable, and every derivation happens inside it. What that is worth "
                + "depends on which token: a device keeps the secret from anybody with access "
                + "to this host, a software token keeps it from anybody who reads this "
                + "deployment's configuration or its backups, and not from the host.")
            : new KeyCustody(
                Tier: "Pkcs11",
                Description: where,
                ProductionReady: false,
                "The token holds keys it is willing to hand out, so the interface is a device's "
                + "and the custody is a file's. Regenerate them sensitive and non-extractable.");
    }

    private byte[] Sign(KeyRef key, byte[] message)
    {
        if (!handles.TryGetValue(key, out var handle))
        {
            throw new KeyUnavailableException(
                $"The token {options.TokenLabel} holds no key labelled {key.Label}, so nothing "
                + "can be derived from it. Provision one with scripts/new-secret-keys.sh.");
        }

        using var mechanism = factories.MechanismFactory.Create(CKM.CKM_SHA256_HMAC);

        return session!.Sign(mechanism, handle, message);
    }
}
