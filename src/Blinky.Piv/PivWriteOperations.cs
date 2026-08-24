using System.Formats.Asn1;
using System.Security.Cryptography;

namespace Blinky.Piv;

/// <summary>
/// The operations that change a token.
/// </summary>
/// <remarks>
/// Kept apart from the read path in a separate file for one reason: everything
/// here can destroy something. A key generated over an existing one cannot be
/// recovered, and a PIN verified with the wrong value moves a counter that only
/// a PUK can move back.
/// </remarks>
public partial class PivSession
{
    private const byte InsGeneralAuthenticate = 0x87;
    private const byte InsGenerateKeyPair = 0x47;
    private const byte InsPutData = 0xDB;
    private const byte InsSetManagementKey = 0xFF;

    /// <summary>
    /// Proves to the card that we hold the management key, and makes the card
    /// prove the same back.
    /// </summary>
    /// <remarks>
    /// Three steps: ask the card for a witness, return it decrypted along with
    /// a challenge of our own, and check the card's answer is that challenge
    /// encrypted. The second half is what a substituted card cannot fake.
    /// </remarks>
    public void AuthenticateManagementKey(ManagementKey managementKey)
    {
        Authenticate(managementKey);
        RegisterRestore(managementKey);
    }

    /// <summary>
    /// Teaches the connection how to get back in after the card is reset.
    /// </summary>
    /// <remarks>
    /// Separate from authenticating because the two come apart: replacing the
    /// management key leaves the card demanding a different value from the one
    /// this was last told about, and a restore holding the old one answers a
    /// reset by failing.
    ///
    /// That is not hypothetical. Personalisation authenticates with the factory
    /// key and then replaces it, so every card being personalised spends the
    /// rest of the operation with a stale restore unless this is called again -
    /// and the rest of the operation is exactly where a reset happens, because
    /// on Windows the card is shared with the logon screen. Seen on token
    /// 29051525: the key was generated, somebody logged in, the card was reset,
    /// and the recovery tried a key the card had stopped accepting a second
    /// earlier.
    /// </remarks>
    private void RegisterRestore(ManagementKey managementKey)
    {

        // Registered so a reset in the middle of a long operation does not end
        // it. Enrolment authenticates here, generates a key, then goes to the
        // server and comes back with a certificate to write - and the card is
        // shared with the operating system for all of that. Recovery selects
        // the applet again, which is exactly what clears this, so it has to be
        // done again on the other side.
        //
        // Not recursive: Authenticate uses Send, and a reset during the
        // restore leaves RestoreSecurityState pointing here, but a second
        // reset in one command already throws before reaching it.
        Connection.RestoreSecurityState = () =>
        {
            try
            {
                Authenticate(managementKey);
                return true;
            }
            catch (PivException)
            {
                return false;
            }
        };
    }

    private void Authenticate(ManagementKey managementKey)
    {
        var algorithm = (byte)managementKey.Algorithm;

        // 7C 02 80 00 - "give me a witness".
        var witnessResponse = Connection.Send(new ApduCommand(InsGeneralAuthenticate,
            p1: algorithm, p2: ManagementKeySlot,
            data: new byte[] { 0x7C, 0x02, 0x80, 0x00 }, le: 0));

        PivStatus.ThrowIfFailed(witnessResponse.Status, "GENERAL AUTHENTICATE (witness)");

        var witness = Unwrap(witnessResponse.Data, 0x80)
            ?? throw new PivProtocolException("The card returned no witness to decrypt.");

        var decrypted = managementKey.Decrypt(witness);
        var challenge = RandomNumberGenerator.GetBytes(managementKey.BlockSize);

        // 7C .. 80 <decrypted witness> 81 <our challenge>
        var payload = new List<byte> { 0x7C, (byte)(4 + decrypted.Length + challenge.Length) };
        payload.Add(0x80);
        payload.Add((byte)decrypted.Length);
        payload.AddRange(decrypted);
        payload.Add(0x81);
        payload.Add((byte)challenge.Length);
        payload.AddRange(challenge);

        var response = Connection.Send(new ApduCommand(InsGeneralAuthenticate,
            p1: algorithm, p2: ManagementKeySlot, data: payload.ToArray(), le: 0));

        if (response.Status.Value == StatusWord.SecurityStatusNotSatisfied)
        {
            throw new PivAuthenticationFailedException(
                "The card rejected the management key. It is neither the value supplied nor, "
                + "if this was the factory key, still at the factory value.");
        }

        PivStatus.ThrowIfFailed(response.Status, "GENERAL AUTHENTICATE (challenge)");

        var answer = Unwrap(response.Data, 0x82)
            ?? throw new PivProtocolException("The card returned no answer to the challenge.");

        // The card proving itself. Skipping this check would leave a swapped
        // or emulated card indistinguishable from the real one.
        if (!CryptographicOperations.FixedTimeEquals(answer, managementKey.Encrypt(challenge)))
        {
            throw new PivAuthenticationFailedException(
                "The card answered the challenge incorrectly. It does not hold this "
                + "management key, whatever it accepted.");
        }
    }

    /// <summary>
    /// Verifies the PIN. A wrong value costs an attempt, and the exception says
    /// how many are left.
    /// </summary>
    public void VerifyPin(ReadOnlySpan<char> pin)
    {
        // PIV pads the PIN to eight bytes with FF.
        Span<byte> padded = stackalloc byte[8];
        padded.Fill(0xFF);

        var written = System.Text.Encoding.ASCII.GetBytes(pin, padded);
        if (written is < 6 or > 8)
        {
            throw new ArgumentException("A PIV PIN is between six and eight characters.",
                nameof(pin));
        }

        var response = Connection.Send(new ApduCommand(InsVerify, p2: PinSlot,
            data: padded.ToArray()));

        if (response.Status.RetriesLeft is { } remaining)
        {
            throw new PivVerificationFailedException(response.Status, "VERIFY PIN", remaining);
        }

        PivStatus.ThrowIfFailed(response.Status, "VERIFY PIN");
    }

    /// <summary>
    /// Generates a key pair in a slot and returns its public key.
    /// </summary>
    /// <remarks>
    /// <b>Destroys whatever the slot held.</b> There is no undo and no copy: the
    /// private key never existed anywhere else. The caller is expected to have
    /// checked the slot first — see <see cref="ReadInventory"/>.
    /// </remarks>
    public PivPublicKey GenerateKeyPair(PivSlot slot, PivAlgorithm algorithm,
        PinPolicy pinPolicy = PinPolicy.Unknown, TouchPolicy touchPolicy = TouchPolicy.Unknown)
    {
        var data = new List<byte> { 0xAC, 0x03, 0x80, 0x01, (byte)algorithm };

        if (pinPolicy is not PinPolicy.Unknown)
        {
            data[1] += 3;
            data.AddRange([0xAA, 0x01, (byte)pinPolicy]);
        }

        if (touchPolicy is not TouchPolicy.Unknown)
        {
            data[1] += 3;
            data.AddRange([0xAB, 0x01, (byte)touchPolicy]);
        }

        var response = Connection.Send(new ApduCommand(InsGenerateKeyPair,
            p1: 0x00, p2: slot.Id, data: data.ToArray(), le: 0));

        PivStatus.ThrowIfFailed(response.Status, $"GENERATE KEY PAIR {slot}");

        return PublicKeyDecoder.Decode(response.Data, algorithm);
    }

    /// <summary>
    /// Signs one block with the key in a slot.
    /// </summary>
    /// <remarks>
    /// The input is a digest for ECDSA, or a fully padded PKCS#1 block for RSA.
    /// If the slot's touch policy asks for it the card blinks here and this call
    /// does not return until a finger arrives or it times out — which is normal,
    /// not a hang. See docs/03-piv-layer.md.
    /// </remarks>
    public byte[] SignWithSlot(PivSlot slot, PivAlgorithm algorithm, ReadOnlySpan<byte> block)
    {
        var payload = new List<byte>();
        var inner = new List<byte> { 0x82, 0x00, 0x81 };

        AppendLength(inner, block.Length);
        inner.AddRange(block);

        payload.Add(0x7C);
        AppendLength(payload, inner.Count);
        payload.AddRange(inner);

        var response = Connection.Send(new ApduCommand(InsGeneralAuthenticate,
            p1: (byte)algorithm, p2: slot.Id, data: payload.ToArray(), le: 0));

        if (response.Status.Value == StatusWord.SecurityStatusNotSatisfied)
        {
            throw new PivAuthenticationFailedException(
                $"Slot {slot} refused to sign: its PIN policy has not been satisfied.");
        }

        PivStatus.ThrowIfFailed(response.Status, $"GENERAL AUTHENTICATE (sign {slot})");

        return Unwrap(response.Data, 0x82)
            ?? throw new PivProtocolException("The card returned no signature.");
    }

    /// <summary>
    /// Writes a certificate into a slot's data object.
    /// </summary>
    /// <remarks>
    /// The first thing in this library that sends more than one APDU of data,
    /// so the outbound chaining in <see cref="PivConnection"/> runs here for
    /// real. Requires the management key to have been authenticated.
    /// </remarks>
    /// <summary>
    /// Yubico's MOVE KEY, which with a destination of <c>FF</c> is a delete.
    /// </summary>
    private const byte InsMoveKey = 0xF6;

    /// <summary>
    /// Destroys the private key in a slot.
    /// </summary>
    /// <remarks>
    /// <para>
    /// PIV has no such command. Standard PIV only lets a key be replaced by
    /// generating over it, which leaves a key there — just a different one —
    /// and that is not the same as an empty slot when somebody is asking
    /// whether a token has been cleared.
    /// </para>
    /// <para>
    /// Yubico added one in firmware 5.7. Older tokens throw here rather than
    /// pretending: the honest answer for a 5.4 is that the key cannot be
    /// deleted, only overwritten, and a caller that wants an empty slot has to
    /// know the difference.
    /// </para>
    /// <para>
    /// Needs the management key, and there is no undo.
    /// </para>
    /// </remarks>
    /// <returns>
    /// False when there was no key to begin with. Not an error: this is a
    /// desired-state operation, and a job retried after a dropped connection
    /// must not fail the second time for having succeeded the first.
    /// </returns>
    public bool DeleteKey(PivSlot slot)
    {
        // P1 is the destination and FF means nowhere; P2 is the slot to move.
        var response = Connection.Send(new ApduCommand(InsMoveKey, p1: 0xFF, p2: slot.Id));

        // 6A88: no such reference data. The slot is already empty, which is
        // where this was trying to get to.
        if (response.Status.Value == 0x6A88)
        {
            return false;
        }

        if (response.Status.Value is 0x6D00 or 0x6A81)
        {
            throw new PivException(response.Status, $"DELETE KEY ({slot})",
                "this firmware cannot delete a key - the instruction arrived in 5.7. "
                + "The only way to remove it is to generate over it.");
        }

        PivStatus.ThrowIfFailed(response.Status, $"DELETE KEY ({slot})");

        return true;
    }

    /// <summary>
    /// Removes the certificate from a slot, leaving the key where it is.
    /// </summary>
    /// <remarks>
    /// <para>
    /// An empty data object, which is how PIV says "there is nothing here".
    /// The private key is untouched and unreachable afterwards for anything
    /// that needed the certificate to find it — which is usually the point: a
    /// credential is being withdrawn, not a token being wiped.
    /// </para>
    /// <para>
    /// Needs the management key. Deleting somebody's certificate is a write.
    /// </para>
    /// </remarks>
    public void DeleteCertificate(PivSlot slot)
    {
        var tag = slot.CertificateObject
            ?? throw new ArgumentException($"Slot {slot} holds no certificate object.",
                nameof(slot));

        // 5C <tag> 53 00 - the object, and nothing in it.
        var data = new List<byte> { 0x5C, (byte)tag.Length };
        data.AddRange(tag);
        data.AddRange([0x53, 0x00]);

        var response = Connection.Send(new ApduCommand(InsPutData,
            p1: 0x3F, p2: 0xFF, data: data.ToArray()));

        PivStatus.ThrowIfFailed(response.Status, $"PUT DATA (delete {slot})");
    }

    public void PutCertificate(PivSlot slot, byte[] der)
    {
        var tag = slot.CertificateObject
            ?? throw new ArgumentException($"Slot {slot} holds no certificate object.",
                nameof(slot));

        // 70 <der>, 71 01 00 (not compressed), FE 00
        var inner = new List<byte> { 0x70 };
        AppendLength(inner, der.Length);
        inner.AddRange(der);
        inner.AddRange([0x71, 0x01, 0x00, 0xFE, 0x00]);

        var body = new List<byte> { 0x53 };
        AppendLength(body, inner.Count);
        body.AddRange(inner);

        var data = new List<byte> { 0x5C, (byte)tag.Length };
        data.AddRange(tag);
        data.AddRange(body);

        var response = Connection.Send(new ApduCommand(InsPutData,
            p1: 0x3F, p2: 0xFF, data: data.ToArray()));

        if (response.Status.Value == StatusWord.SecurityStatusNotSatisfied)
        {
            throw new PivAuthenticationFailedException(
                $"Writing to slot {slot} needs the management key authenticated first.");
        }

        PivStatus.ThrowIfFailed(response.Status, $"PUT DATA {slot}");
    }

    /// <summary>
    /// Writes the two data objects that make a card usable by Windows, unless
    /// it already has them.
    /// </summary>
    /// <remarks>
    /// <para>
    /// See <see cref="PivCardObjects"/> for why. In short: without a CHUID and
    /// a CCC the inbox minidriver finds the certificate, cannot associate a
    /// key container with it, and answers <c>NTE_BAD_KEYSET</c>.
    /// </para>
    /// <para>
    /// Not overwritten when present. The GUID inside a CHUID is how Windows
    /// tells one card from another, and replacing it on a card somebody
    /// already enrolled would look, from the operating system's side, like a
    /// different card wearing the same certificates.
    /// </para>
    /// <para>
    /// Needs the management key, like every other write.
    /// </para>
    /// </remarks>
    /// <returns>What it had to write, for the caller to report.</returns>
    public CardIdentityWritten EnsureCardIdentity(DateOnly chuidExpires)
    {
        var chuid = WriteIfAbsent(PivCardObjects.CardholderUniqueIdentifier,
            () => PivCardObjects.BuildChuid(chuidExpires), "CHUID");

        var ccc = WriteIfAbsent(PivCardObjects.CardCapabilityContainer,
            PivCardObjects.BuildCapabilityContainer, "CCC");

        return new CardIdentityWritten(chuid, ccc);
    }

    private bool WriteIfAbsent(byte[] tag, Func<byte[]> build, string what)
    {
        if (ReadObject(tag) is { Length: > 0 })
        {
            return false;
        }

        WriteObject(tag, build(), what);
        return true;
    }

    /// <summary>Writes a data object, replacing whatever is there.</summary>
    private void WriteObject(byte[] tag, byte[] value, string what)
    {
        var body = new List<byte> { 0x53 };
        AppendLength(body, value.Length);
        body.AddRange(value);

        var data = new List<byte> { 0x5C, (byte)tag.Length };
        data.AddRange(tag);
        data.AddRange(body);

        var response = Connection.Send(new ApduCommand(InsPutData,
            p1: 0x3F, p2: 0xFF, data: data.ToArray()));

        if (response.Status.Value == StatusWord.SecurityStatusNotSatisfied)
        {
            throw new PivAuthenticationFailedException(
                $"Writing the {what} needs the management key authenticated first.");
        }

        PivStatus.ThrowIfFailed(response.Status, $"PUT DATA ({what})");
    }

    /// <summary>
    /// The management key this card keeps behind its PIN, or null if it keeps
    /// none.
    /// </summary>
    /// <remarks>
    /// Call after VerifyPin. The object is refused otherwise, and the refusal
    /// arrives looking like an absent object rather than a denied one - so a
    /// card whose key is here reads as a card whose key is not, and the next
    /// write fails on the management key instead.
    /// </remarks>
    /// <summary>
    /// Replaces the card's management key, and optionally stores it behind the
    /// PIN so the card stays manageable by anything that looks there.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Needs the current management key authenticated first, like every other
    /// write. The card is not asked to confirm the old value again - holding an
    /// authenticated session <em>is</em> that proof.
    /// </para>
    /// <para>
    /// The order is deliberate: the PRINTED copy is written first, while the
    /// session is still authenticated under the old key. Setting the key first
    /// and then failing to record it leaves a card nobody can open again, and
    /// no amount of care afterwards recovers from that.
    /// </para>
    /// <para>
    /// <paramref name="alsoBehindPin"/> is what lets Blinky and the YubiKey
    /// minidriver share a card. That driver takes ownership of any card whose
    /// management key it does not recognise - replaces it, hides its own copy
    /// here, and blocks the PUK - and a card it has done that to is one this
    /// CMS can no longer write to. A card that already keeps its key here is
    /// one it leaves alone.
    /// </para>
    /// </remarks>
    public void SetManagementKey(ManagementKey newKey, bool alsoBehindPin)
    {
        if (alsoBehindPin)
        {
            WriteObject(PivCardObjects.PrintedInformation, newKey.PrintedObjectValue(),
                "protected management key");
        }

        var response = Connection.Send(new ApduCommand(InsSetManagementKey,
            p1: 0xFF, p2: 0xFF, data: newKey.SetCommandData()));

        if (response.Status.Value == StatusWord.SecurityStatusNotSatisfied)
        {
            throw new PivAuthenticationFailedException(
                "Replacing the management key needs the current one authenticated first.");
        }

        PivStatus.ThrowIfFailed(response.Status, "SET MANAGEMENT KEY");

        // The card now wants this one. A restore still holding the previous
        // value would turn the next card reset into a failed operation.
        RegisterRestore(newKey);
    }

    public ManagementKey? ReadProtectedManagementKey(PivAlgorithm algorithm)
    {
        var data = ReadObject(PivCardObjects.PrintedInformation);

        return data is null ? null : ProtectedManagementKey.Parse(data, algorithm);
    }

    private byte[]? ReadObject(byte[] tag)
    {
        var data = new List<byte> { 0x5C, (byte)tag.Length };
        data.AddRange(tag);

        var response = Connection.Send(new ApduCommand(InsGetData,
            p1: 0x3F, p2: 0xFF, data: data.ToArray(), le: 0));

        // 6A82 is the card saying the object is not there, which is the normal
        // answer on a card nobody has provisioned and not a failure.
        return response.IsSuccess ? response.Data : null;
    }

    /// <summary>Appends a BER length: short form, or 81/82 as needed.</summary>
    internal static void AppendLength(List<byte> target, int length)
    {
        switch (length)
        {
            case < 0x80:
                target.Add((byte)length);
                break;
            case <= 0xFF:
                target.Add(0x81);
                target.Add((byte)length);
                break;
            default:
                target.Add(0x82);
                target.Add((byte)(length >> 8));
                target.Add((byte)(length & 0xFF));
                break;
        }
    }

    /// <summary>Pulls one tag out of a 7C-wrapped dynamic authentication template.</summary>
    private static byte[]? Unwrap(byte[] response, byte tag)
    {
        var outer = Tlv.ParseBer(response);
        if (!outer.TryGetValue(0x7C, out var template))
        {
            return null;
        }

        return Tlv.ParseBer(template).TryGetValue(tag, out var value) ? value : null;
    }
}

/// <summary>
/// The card refused because a PIN or the management key has not been
/// satisfied — as opposed to the command being wrong.
/// </summary>
public sealed class PivAuthenticationFailedException(string message) : PivException(
    new StatusWord(StatusWord.SecurityStatusNotSatisfied), "authentication", message);

/// <summary>
/// A public key read off a card.
/// </summary>
/// <remarks>
/// Named PivPublicKey rather than PublicKey on purpose: the X.509 namespace
/// already has one, and a type that shadows it in this file would be a small
/// trap for every later reader.
/// </remarks>
public sealed record PivPublicKey(PivAlgorithm Algorithm, byte[] SubjectPublicKeyInfo)
{
    public AsymmetricAlgorithm Create()
    {
        if (Algorithm is PivAlgorithm.EccP256 or PivAlgorithm.EccP384)
        {
            var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(SubjectPublicKeyInfo, out _);

            return ecdsa;
        }

        var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(SubjectPublicKeyInfo, out _);

        return rsa;
    }
}

/// <summary>Turns the card's <c>7F49</c> template into a SubjectPublicKeyInfo.</summary>
internal static class PublicKeyDecoder
{
    public static PivPublicKey Decode(byte[] response, PivAlgorithm algorithm)
    {
        var outer = Tlv.ParseBer(response);

        // 7F49 is the public key template, and it is now read as the single
        // two-byte tag it is. Some cards return the contents unwrapped, so a
        // missing template is not an error - it means the tags are already at
        // the top level.
        var template = outer.TryGetValue(0x7F49, out var nested)
            ? Tlv.ParseBer(nested)
            : outer;

        return algorithm switch
        {
            PivAlgorithm.EccP256 or PivAlgorithm.EccP384 =>
                new PivPublicKey(algorithm, EncodeEcc(Require(template, 0x86), algorithm)),
            PivAlgorithm.Rsa1024 or PivAlgorithm.Rsa2048 or PivAlgorithm.Rsa3072
                or PivAlgorithm.Rsa4096 =>
                new PivPublicKey(algorithm,
                    EncodeRsa(Require(template, 0x81), Require(template, 0x82))),
            _ => throw new PivProtocolException(
                $"{algorithm} public keys are not decoded by this build."),
        };
    }

    private static byte[] Require(Dictionary<int, byte[]> template, int tag) =>
        template.TryGetValue(tag, out var value)
            ? value
            : throw new PivProtocolException(
                $"The generated key response has no tag {tag:X2}.");

    private static byte[] EncodeEcc(byte[] point, PivAlgorithm algorithm)
    {
        var curve = algorithm is PivAlgorithm.EccP384
            ? ECCurve.NamedCurves.nistP384
            : ECCurve.NamedCurves.nistP256;

        var size = (point.Length - 1) / 2;

        using var ecdsa = ECDsa.Create(new ECParameters
        {
            Curve = curve,
            Q = new ECPoint
            {
                X = point[1..(1 + size)],
                Y = point[(1 + size)..],
            },
        });

        return ecdsa.ExportSubjectPublicKeyInfo();
    }

    private static byte[] EncodeRsa(byte[] modulus, byte[] exponent)
    {
        using var rsa = RSA.Create(new RSAParameters
        {
            Modulus = modulus,
            Exponent = exponent,
        });

        return rsa.ExportSubjectPublicKeyInfo();
    }
}
