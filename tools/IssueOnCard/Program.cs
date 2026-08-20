// Blinky - issue a credential onto a card.
//
// THIS WRITES TO A TOKEN. It generates a key pair in a slot, which destroys
// whatever that slot held, and there is no copy anywhere - the private key
// never existed off the card.
//
//     dotnet run --project tools/IssueOnCard -- \
//         --serial 29177301 --slot 9C --pin 123456 --ca ca
//
// It refuses a slot that is not empty unless --force is given, and it names
// what it would destroy first.
//
// The whole of patch 0023 and 0024 in one run: authenticate the management key,
// generate a key on the card, attest it and verify the chain to the pinned
// Yubico root, have the card sign its own certificate request, issue from the
// built-in CA, write the certificate back, and read it off again to check.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Blinky.Pki;
using Blinky.Pki.BuiltIn;
using Blinky.Piv;
using Blinky.Piv.Attestation;
using Blinky.Piv.Pcsc;

var arguments = ParseArguments(args);

var serial = arguments.GetValueOrDefault("serial");
var slotName = arguments.GetValueOrDefault("slot", "9C");
var pin = arguments.GetValueOrDefault("pin", "123456");
var caDirectory = arguments.GetValueOrDefault("ca", "ca");
var caPassword = arguments.GetValueOrDefault("ca-password", "blinky");
var force = arguments.ContainsKey("force");

if (string.IsNullOrWhiteSpace(serial))
{
    Console.Error.WriteLine("--serial is required. This writes to a token; naming it is the point.");
    return 2;
}

if (!PcscContext.IsSupported)
{
    Console.Error.WriteLine("Windows only in this build.");
    return 4;
}

var slot = PivSlot.Credentials.FirstOrDefault(s =>
    s.Name.Equals(slotName, StringComparison.OrdinalIgnoreCase));

if (slot.Id == 0)
{
    Console.Error.WriteLine($"--slot must be one of {string.Join(", ", PivSlot.Credentials)}");
    return 2;
}

using var context = PcscContext.Establish();

foreach (var reader in context.ListReaders())
{
    using var card = context.Connect(reader);
    if (card is null)
    {
        continue;
    }

    using var connection = new PivConnection(card, ownsTransport: false);
    var session = new PivSession(connection);
    using var transaction = connection.BeginTransaction();

    if (!session.Select() || session.GetSerialNumber()?.ToString() != serial)
    {
        continue;
    }

    return Issue(session, reader);
}

Console.Error.WriteLine($"No token with serial {serial} is in a reader.");
return 3;

int Issue(PivSession session, string reader)
{
    Console.WriteLine($"token {serial} in {reader}");

    // 1. What is already there. A key generated over an existing one cannot be
    //    recovered, so this is checked before anything is authenticated.
    var existing = session.GetSlotMetadata(slot);
    if (existing is not null && !force)
    {
        Console.Error.WriteLine(
            $"  slot {slot} already holds a {existing.Algorithm} key ({existing.Origin}). "
            + "Generating would destroy it. Pass --force if that is intended.");

        return 1;
    }

    // 2. The management key, whose algorithm is read rather than assumed:
    //    firmware below 5.7 ships 3DES and 5.7 or later ships AES-192.
    var metadata = session.GetManagementKeyMetadata();
    if (metadata is null)
    {
        Console.Error.WriteLine("  this firmware cannot report its management key algorithm");
        return 1;
    }

    Console.WriteLine($"  management key {metadata.Algorithm}, default={metadata.IsDefault}");

    session.AuthenticateManagementKey(ManagementKey.Default(metadata.Algorithm));
    Console.WriteLine("  management key authenticated, and the card proved it back");

    // 3. Generate. This is the destructive step.
    var generated = session.GenerateKeyPair(slot, PivAlgorithm.EccP256,
        PinPolicy.Once, TouchPolicy.Never);

    Console.WriteLine($"  generated {generated.Algorithm} in {slot}");

    // 4. Ask the card to vouch for it, and check that against the pinned root
    //    before any CA is asked to sign anything.
    var leaf = session.Attest(slot);
    var intermediate = session.GetAttestationCertificate();

    if (leaf is null || intermediate is null)
    {
        Console.Error.WriteLine("  the card produced no attestation for the new key");
        return 1;
    }

    var verifier = new AttestationVerifier(YubicoRoots.PivAttestation);
    var attestation = verifier.Verify(leaf, intermediate, slot, session.GetSerialNumber(),
        generated.SubjectPublicKeyInfo);

    Console.WriteLine($"  attestation {attestation}");
    if (!attestation.IsTrusted)
    {
        return 1;
    }

    // 5. The card signs its own request. The PIN is needed because the key was
    //    generated with a PIN policy of Once.
    session.VerifyPin(pin);

    var generator = new PivSignatureGenerator(session, slot, generated);
    var request = new CertificateRequest(
        new X500DistinguishedName("CN=blinky-issued"),
        generator.PublicKey,
        HashAlgorithmName.SHA256);

    var csr = request.CreateSigningRequest(generator);
    Console.WriteLine($"  card signed a {csr.Length} byte certificate request");

    // 6. Issue.
    using var ca = BuiltInCaFactory.LoadFromDirectory(caDirectory, caPassword,
        allowFileKeys: true, crlValidity: TimeSpan.FromHours(6));

    var profile = new IssuanceProfile("smartcard-logon", slot.Name, "ECCP256", 365,
        ["1.3.6.1.5.5.7.3.2", BuiltInCertificateAuthority.SmartCardLogonOid],
        IncludeUpnSan: true, IncludeSidExtension: true);

    var issued = ca.IssueAsync(new CertificateRequestContext(
        csr,
        new AttestedKey(long.Parse(serial), slot.Name, generated.SubjectPublicKeyInfo,
            attestation.Attestation!.PinPolicy.ToString(),
            attestation.Attestation.TouchPolicy.ToString()),
        new CardholderIdentity("Jan Kowalski", "jkowalski@corp.example",
            "S-1-5-21-1-2-3-1104", null),
        profile)).GetAwaiter().GetResult();

    Console.WriteLine($"  issued by {ca.Issuer.Subject}");
    Console.WriteLine($"    serial   {issued.SerialNumber}");
    Console.WriteLine($"    subject  {issued.Certificate.Subject}");

    // 7. Write it back, which is the first time this library sends more than
    //    one APDU of data.
    session.PutCertificate(slot, issued.Certificate.RawData);
    Console.WriteLine($"  wrote {issued.Certificate.RawData.Length} bytes into {slot}");

    // 8. Read it off again. A 9000 means the card accepted the write, not that
    //    what came back is what went in.
    var readBack = session.GetCertificateAsX509(slot);
    if (readBack is null)
    {
        Console.Error.WriteLine("  the slot reads back empty");
        return 1;
    }

    var matches = readBack.Thumbprint == issued.Certificate.Thumbprint;
    Console.WriteLine($"  read back {readBack.Subject}, same certificate: {matches}");

    return matches ? 0 : 1;
}

static Dictionary<string, string> ParseArguments(string[] args)
{
    var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    for (var i = 0; i < args.Length; i++)
    {
        if (!args[i].StartsWith("--", StringComparison.Ordinal))
        {
            continue;
        }

        var name = args[i][2..];
        var hasValue = i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal);

        result[name] = hasValue ? args[++i] : "true";
    }

    return result;
}
