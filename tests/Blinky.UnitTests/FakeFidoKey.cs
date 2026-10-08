using System.Formats.Cbor;
using Blinky.Fido;

namespace Blinky.UnitTests;

/// <summary>
/// A CTAP 2.1 authenticator in memory, after KeyEnroll's <c>fake_authenticator.py</c>:
/// enough of clientPIN, authenticatorConfig and makeCredential to hold the
/// engine to the rules a real key enforces.
/// </summary>
/// <remarks>
/// The rules that matter, because the engine's order depends on them: no PIN token
/// while a forced change is pending (CTAP 2.1 §6.5.5.7 answers
/// PIN_POLICY_VIOLATION); raising the minimum above the current PIN's length
/// forces a change; three wrong PINs in a row block until power-up, eight in all
/// block for good.
/// </remarks>
internal sealed class FakeFidoKey(List<string> log, bool supportsConfig = true, long? serial = 29177301) : IFidoKey
{
    private readonly List<(string RpId, byte[] Id)> credentials = [];
    private string? pin;
    private int retries = 8;
    private int consecutive;
    private int minPinLength = 4;
    private bool forcePinChange;
    private bool token;

    /// <summary>The next SetPin or ChangePin is refused as a policy violation, once.</summary>
    public bool RefuseNextPin { get; set; }

    public IReadOnlyList<(string RpId, byte[] Id)> Credentials => credentials;

    public bool ForcePinChangePending => forcePinChange;

    public string? CurrentPin => pin;

    public static FakeFidoKey WithPin(List<string> log, string pin, bool supportsConfig = true)
    {
        var key = new FakeFidoKey(log, supportsConfig) { pin = pin };
        return key;
    }

    public void Excludes(string rpId, byte[] id) => credentials.Add((rpId, id));

    public FidoKeyInfo Info() => new(serial, "5.7.1", Guid.Parse("fa2b99dc-9e39-4257-8f92-4a30d23c4118"),
        supportsConfig ? ["FIDO_2_0", "FIDO_2_1"] : ["FIDO_2_0"], SupportsPin: true, PinSet: pin is not null,
        minPinLength, forcePinChange, supportsConfig, supportsConfig, 25 - credentials.Count);

    public int? PinRetries() => retries;

    public void SetPin(string next)
    {
        log.Add("SetPin");
        if (pin is not null)
        {
            throw new FidoException(FidoError.Other, "PIN already set");
        }

        Policy(next);
        pin = next;
    }

    public void ChangePin(string current, string next)
    {
        log.Add("ChangePin");
        Check(current);
        Policy(next);
        pin = next;
        forcePinChange = false;
        token = false;
    }

    public void VerifyPin(string value)
    {
        log.Add("VerifyPin");

        if (pin is null)
        {
            throw new FidoException(FidoError.PinNotSet, "no PIN");
        }

        if (forcePinChange)
        {
            throw new FidoException(FidoError.PinPolicyViolation, "a PIN change is pending; no token is issued");
        }

        Check(value);
        token = true;
    }

    public void SetMinPinLength(int length)
    {
        log.Add($"SetMinPinLength:{length}");
        Configurable();

        if (length < minPinLength)
        {
            throw new FidoException(FidoError.PinPolicyViolation, "the minimum cannot go down");
        }

        minPinLength = length;
        if (pin is not null && pin.Length < length)
        {
            forcePinChange = true;
        }
    }

    public void ForceChangePin()
    {
        log.Add("ForceChangePin");
        Configurable();
        forcePinChange = true;
        token = false;
    }

    public void Reset()
    {
        log.Add("Reset");
        credentials.Clear();
        pin = null;
        retries = 8;
        minPinLength = 4;
        forcePinChange = false;
    }

    public FidoMadeCredential MakeCredential(FidoCredentialRequest request, string value, Action touch)
    {
        log.Add($"MakeCredential:{request.RpId}");

        if (forcePinChange)
        {
            throw new FidoException(FidoError.PinPolicyViolation, "a PIN change is pending; no token is issued");
        }

        Check(value);

        if (request.Exclude.Any(x => credentials.Any(c => c.RpId == request.RpId && c.Id.SequenceEqual(x))))
        {
            throw new FidoException(FidoError.CredentialExcluded, "excluded");
        }

        touch();

        var id = Guid.NewGuid().ToByteArray();
        credentials.Add((request.RpId, id));

        var statement = new CborWriter();
        statement.WriteStartMap(2);
        statement.WriteTextString("alg");
        statement.WriteInt32(-7);
        statement.WriteTextString("sig");
        statement.WriteByteString([0x30, 0x45, 0x02]);
        statement.WriteEndMap();

        byte[] authData = [.. request.ClientDataHash[..32], 0x45, 0, 0, 0, 1, .. id];
        return new FidoMadeCredential(id, AttestationObjects.Build("packed", authData, statement.Encode()));
    }

    public void Dispose()
    {
    }

    private void Check(string value)
    {
        if (retries == 0)
        {
            throw new FidoException(FidoError.PinBlocked, "blocked");
        }

        if (consecutive >= 3)
        {
            throw new FidoException(FidoError.PinAuthBlocked, "power-cycle");
        }

        if (value != pin)
        {
            retries--;
            consecutive++;
            throw new FidoException(retries == 0 ? FidoError.PinBlocked
                : consecutive >= 3 ? FidoError.PinAuthBlocked
                : FidoError.PinInvalid, "wrong PIN");
        }

        consecutive = 0;
        retries = 8;
    }

    private void Policy(string next)
    {
        if (RefuseNextPin || next.Length < minPinLength || Fido2Pin.IsTrivial(next))
        {
            RefuseNextPin = false;
            throw new FidoException(FidoError.PinPolicyViolation, "refused by the key's PIN policy");
        }
    }

    private void Configurable()
    {
        if (!supportsConfig)
        {
            throw new FidoException(FidoError.Unsupported, "no authenticatorConfig");
        }

        if (!token)
        {
            throw new FidoException(FidoError.PinPolicyViolation, "no token for authenticatorConfig");
        }
    }
}
