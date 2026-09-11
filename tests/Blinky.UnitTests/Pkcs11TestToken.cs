using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Blinky.Secrets;

namespace Blinky.UnitTests;

/// <summary>
/// A scratch PKCS#11 token, provisioned the way a deployment would be.
/// </summary>
/// <remarks>
/// <para>
/// SoftHSM2 is what this is run against, and almost nothing here says so. The
/// token is created, the PIN is set and the keys are generated through the
/// standard, because that is the point being tested: if provisioning needed a
/// vendor tool, "add a real HSM later" would be a different procedure rather
/// than the same one against a different module.
/// </para>
/// <para>
/// The one exception is the scratch store. A module keeps its tokens somewhere,
/// and where is the module's own business - SoftHSM reads an environment
/// variable for it, and a test that did not set it would create its token in
/// whatever store the developer actually uses. That is a laboratory concern and
/// it lives here rather than in the product.
/// </para>
/// </remarks>
public sealed class Pkcs11TestToken : IDisposable
{
    /// <summary>The label the provider looks for.</summary>
    public const string TokenLabel = "blinky-test";

    public const string UserPin = "123456";

    private const string SoPin = "87654321";

    /// <summary>
    /// A key generated inside the token, which is what a new deployment gets.
    /// </summary>
    public const string GeneratedLabel = "blinky/management-key/v1";

    /// <summary>
    /// A key imported from an existing master, which is what a deployment
    /// migrating off configuration gets. Its value is
    /// <see cref="ImportedMaster"/> extracted, so the derivations either side of
    /// the migration have to agree.
    /// </summary>
    public const string ImportedLabel = "blinky/puk-kek/v2";

    /// <summary>A key the token will hand out, to prove that it is refused.</summary>
    public const string ExtractableLabel = "blinky/management-key/v9";

    private readonly string scratch;
    private readonly IPkcs11Library library;
    private readonly ISession session;

    public Pkcs11TestToken()
    {
        Module = Pkcs11Module.Path
                 ?? throw new InvalidOperationException(Pkcs11Module.WhyNot);

        scratch = System.IO.Directory.CreateTempSubdirectory("blinky-pkcs11-").FullName;

        var tokens = Path.Combine(scratch, "tokens");
        System.IO.Directory.CreateDirectory(tokens);

        if (Module.Contains("softhsm", StringComparison.OrdinalIgnoreCase))
        {
            var conf = Path.Combine(scratch, "softhsm2.conf");

            File.WriteAllText(conf,
                $"directories.tokendir = {tokens.Replace('\\', '/')}/\n"
                + "objectstore.backend = file\n"
                + "log.level = ERROR\n");

            Environment.SetEnvironmentVariable("SOFTHSM2_CONF", conf);
        }

        // Through the same code the operator's tool runs, so that a change
        // which breaks provisioning breaks these tests rather than passing them
        // against a token nobody could have created.
        Pkcs11Provisioning.InitialiseToken(Module, TokenLabel, SoPin, UserPin);

        using (var provisioning = new Pkcs11Provisioning(Module, TokenLabel, UserPin))
        {
            provisioning.Generate(new KeyRef(KeyPurpose.ManagementKeyMaster, 1));
            provisioning.Import(new KeyRef(KeyPurpose.PukKek, 2), ImportedMaster);
        }

        var factories = new Pkcs11InteropFactories();

        library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(
            factories, Module, AppType.MultiThreaded);

        var slot = library.GetSlotList(SlotsType.WithTokenPresent)
            .First(s => string.Equals(s.GetTokenInfo().Label.Trim(), TokenLabel,
                StringComparison.Ordinal));

        session = slot.OpenSession(SessionType.ReadWrite);
        session.Login(CKU.CKU_USER, UserPin);

        // The one key provisioning will not make, because it is the mistake the
        // provider has to refuse: sensitive off and extractable on.
        Extractable(factories, ExtractableLabel);
    }

    /// <summary>The module under test.</summary>
    public string Module { get; }

    /// <summary>
    /// The master a migrating deployment already has in its configuration.
    /// </summary>
    public static byte[] ImportedMaster
    {
        get
        {
            var master = new byte[32];
            Array.Fill(master, (byte)0x5A);
            return master;
        }
    }

    /// <summary>
    /// What actually goes into the token: the extract of that master, which is
    /// what makes the derivation either side of a migration identical.
    /// </summary>
    public static byte[] ImportedPrk => System.Security.Cryptography.HKDF.Extract(
        System.Security.Cryptography.HashAlgorithmName.SHA256, ImportedMaster, salt: null);

    public void Dispose()
    {
        try
        {
            session.Logout();
        }
        catch (Pkcs11Exception)
        {
            // A token that has already forgotten this session is not a test
            // failure.
        }

        session.Dispose();
        library.Dispose();

        try
        {
            System.IO.Directory.Delete(scratch, recursive: true);
        }
        catch (IOException)
        {
            // A scratch directory the module still holds open outlives the
            // test run and is cleaned up by the operating system. Not worth
            // failing a green suite over.
        }
    }

    /// <summary>
    /// A key the token will hand out, which provisioning refuses to create and
    /// the provider has to refuse to use.
    /// </summary>
    private void Extractable(Pkcs11InteropFactories factories, string label)
    {
        List<IObjectAttribute> template =
        [
            factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
            factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET),
            factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, label),
            factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
            factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true),
            factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, false),
            factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, true),
            factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN, true),
            factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY, true),
            factories.ObjectAttributeFactory.Create(CKA.CKA_VALUE_LEN, 32U),
        ];

        using var mechanism = factories.MechanismFactory.Create(CKM.CKM_GENERIC_SECRET_KEY_GEN);

        session.GenerateKey(mechanism, template);
    }
}

/// <summary>
/// Where the module is, or why these tests did not run.
/// </summary>
/// <remarks>
/// A skip with a reason rather than a test that quietly passes. CI runs on
/// windows-latest with no module installed, so these skip there and the status
/// files say so; the documented way to run them is in docs/09-lab.md.
/// </remarks>
public static class Pkcs11Module
{
    private static readonly string[] WellKnown =
    [
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/lib64/softhsm/libsofthsm2.so",
        "/usr/local/lib/softhsm/libsofthsm2.so",
        "/opt/homebrew/lib/softhsm/libsofthsm2.so",
        "C:\\SoftHSM2\\lib\\softhsm2-x64.dll",
    ];

    public static string? Path { get; } = Locate();

    public static string WhyNot =>
        "No PKCS#11 module was found. Set BLINKY_PKCS11_MODULE to one, or install SoftHSM2 - "
        + "see docs/09-lab.md.";

    private static string? Locate()
    {
        var configured = Environment.GetEnvironmentVariable("BLINKY_PKCS11_MODULE");

        if (!string.IsNullOrWhiteSpace(configured))
        {
            // Named explicitly and missing is a mistake worth failing on rather
            // than skipping past: somebody meant to run these.
            return File.Exists(configured)
                ? configured
                : throw new FileNotFoundException(
                    $"BLINKY_PKCS11_MODULE points at {configured}, which does not exist.");
        }

        return Array.Find(WellKnown, File.Exists);
    }
}

/// <summary>
/// A fact that needs a PKCS#11 module, and says so when there is not one.
/// </summary>
public sealed class RequiresPkcs11ModuleAttribute : FactAttribute
{
    public RequiresPkcs11ModuleAttribute()
    {
        if (Pkcs11Module.Path is null)
        {
            Skip = Pkcs11Module.WhyNot;
        }
    }
}
