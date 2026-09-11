using System.Security.Cryptography;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

namespace Blinky.Secrets;

/// <summary>
/// Puts Blinky's keys into a token, and nothing else.
/// </summary>
/// <remarks>
/// <para>
/// Separate from <see cref="Pkcs11KeyProvider"/> on purpose. Creating objects
/// is the one operation that writes to a token, and a service that can create
/// keys is a service that can create the wrong ones - or two of them, which is
/// worse, because then which key signs is whichever the module returns first.
/// The API opens a read-only session and never calls anything here.
/// </para>
/// <para>
/// Standard calls throughout, so the same procedure provisions a software token
/// and a device. Only <see cref="InitialiseToken"/> is likely to be refused by
/// real hardware, which is initialised by whoever owns it long before Blinky
/// sees it - so it is a separate step rather than part of the others.
/// </para>
/// </remarks>
public sealed class Pkcs11Provisioning : IDisposable
{
    private readonly Pkcs11InteropFactories factories = new();
    private readonly IPkcs11Library library;
    private readonly ISession session;

    public Pkcs11Provisioning(string module, string tokenLabel, string pin)
    {
        library = Load(new Pkcs11InteropFactories(), module);

        var slot = library.GetSlotList(SlotsType.WithTokenPresent)
                       .FirstOrDefault(s => string.Equals(
                           s.GetTokenInfo().Label.Trim(), tokenLabel, StringComparison.Ordinal))
                   ?? throw new KeyUnavailableException(
                       $"No token labelled {tokenLabel} is present in {module}.");

        session = slot.OpenSession(SessionType.ReadWrite);
        session.Login(CKU.CKU_USER, pin);
    }

    /// <summary>
    /// Creates the token itself, for a module that lets an application do that.
    /// </summary>
    /// <remarks>
    /// A software token is created here; a device is usually initialised by its
    /// own tooling and will refuse this, which is why it is not part of the
    /// constructor.
    /// </remarks>
    public static void InitialiseToken(string module, string tokenLabel, string soPin,
        string userPin, int slotIndex = 0)
    {
        var factories = new Pkcs11InteropFactories();

        using var library = Load(factories, module);

        var slots = library.GetSlotList(SlotsType.WithOrWithoutTokenPresent);

        if (slots.Count <= slotIndex)
        {
            throw new KeyUnavailableException(
                $"{module} offers {slots.Count} slot(s), so there is no slot {slotIndex} to "
                + "initialise a token in.");
        }

        slots[slotIndex].InitToken(soPin, tokenLabel);

        using var session = slots[slotIndex].OpenSession(SessionType.ReadWrite);

        session.Login(CKU.CKU_SO, soPin);
        session.InitPin(userPin);
        session.Logout();
    }

    /// <summary>
    /// A new key, generated inside the token and unable to leave it.
    /// </summary>
    /// <remarks>
    /// What a new deployment gets. Nothing outside the token ever sees this
    /// value, which is the strongest form of the arrangement and the reason to
    /// prefer it wherever there are no cards already in the field.
    /// </remarks>
    public void Generate(KeyRef key)
    {
        Refuse(key);

        var template = Template(key);

        template.Add(factories.ObjectAttributeFactory.Create(CKA.CKA_VALUE_LEN, 32U));

        using var mechanism = factories.MechanismFactory.Create(CKM.CKM_GENERIC_SECRET_KEY_GEN);

        session.GenerateKey(mechanism, template);
    }

    /// <summary>
    /// An existing master, brought into the token so that no card changes.
    /// </summary>
    /// <remarks>
    /// <para>
    /// What goes in is not the master but its HKDF extract, and that is the
    /// whole trick: every management key this deployment ever wrote was one
    /// HMAC block under that extract, so a token holding it derives the values
    /// the cards are already holding. Without this, moving an existing
    /// deployment onto a device would mean a re-key job on every token in the
    /// field.
    /// </para>
    /// <para>
    /// This is the one moment a secret crosses into the token, and it is a
    /// provisioning step run by a person rather than something the service can
    /// do. The master was in this deployment's configuration already, so
    /// nothing is exposed that was not; what changes is that afterwards it does
    /// not have to be.
    /// </para>
    /// </remarks>
    public void Import(KeyRef key, byte[] master)
    {
        ArgumentNullException.ThrowIfNull(master);

        if (master.Length < 32)
        {
            throw new KeyUnavailableException(
                $"The master is {master.Length} bytes; 32 is the minimum.");
        }

        Refuse(key);

        var template = Template(key);

        var prk = HKDF.Extract(HashAlgorithmName.SHA256, master, salt: null);

        try
        {
            template.Add(factories.ObjectAttributeFactory.Create(CKA.CKA_VALUE, prk));

            session.CreateObject(template);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(prk);
        }
    }

    /// <summary>What the token holds under Blinky's labels, with no values.</summary>
    public IReadOnlyList<ProvisionedKey> List()
    {
        var search = new List<IObjectAttribute>
        {
            factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
        };

        var keys = new List<ProvisionedKey>();

        foreach (var handle in session.FindAllObjects(search))
        {
            var attributes = session.GetAttributeValue(handle,
                [CKA.CKA_LABEL, CKA.CKA_SENSITIVE, CKA.CKA_EXTRACTABLE]);

            var label = attributes[0].GetValueAsString();

            if (!label.StartsWith("blinky/", StringComparison.Ordinal))
            {
                continue;
            }

            keys.Add(new ProvisionedKey(label, attributes[1].GetValueAsBool(),
                attributes[2].GetValueAsBool()));
        }

        return keys;
    }

    public void Dispose()
    {
        try
        {
            session.Logout();
        }
        catch (Pkcs11Exception)
        {
            // Nothing to salvage and nothing to report.
        }

        session.Dispose();
        library.Dispose();
    }

    private static IPkcs11Library Load(Pkcs11InteropFactories factories, string module)
    {
        if (!File.Exists(module))
        {
            throw new KeyUnavailableException($"The PKCS#11 module {module} does not exist.");
        }

        return factories.Pkcs11LibraryFactory.LoadPkcs11Library(
            factories, module, AppType.MultiThreaded);
    }

    /// <summary>
    /// Refuses to write a second object under a label that already has one.
    /// </summary>
    /// <remarks>
    /// Two keys with one label is the failure this whole file exists to
    /// prevent: nothing would look wrong, and half the fleet would be
    /// diversified under a key the other half does not have.
    /// </remarks>
    private void Refuse(KeyRef key)
    {
        var existing = session.FindAllObjects(
        [
            factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
            factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, key.Label),
        ]);

        if (existing.Count > 0)
        {
            throw new KeyUnavailableException(
                $"The token already holds {key.Label}. Rotating means a new version beside it, "
                + "not a second object with the same name - raise the version instead.");
        }
    }

    private List<IObjectAttribute> Template(KeyRef key) =>
    [
        factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
        factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET),
        factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, key.Label),

        // On the token rather than in the session, so it survives the process.
        factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),

        // The three that matter. Private keeps it behind the PIN, sensitive
        // stops the value being read back, and not extractable stops it being
        // wrapped out under another key - which is the loophole that makes the
        // other two decorative.
        factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true),
        factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, true),
        factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, false),

        factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN, true),
        factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY, true),
    ];
}

/// <summary>One key the token holds, described without its value.</summary>
public sealed record ProvisionedKey(string Label, bool Sensitive, bool Extractable);
