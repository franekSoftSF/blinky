using System.Text;
using Yubico.YubiKey;
using Yubico.YubiKey.Fido2;
using Yubico.YubiKey.Fido2.Commands;
using Yubico.YubiKey.Fido2.Cose;

namespace Blinky.Fido.Yubico;

/// <summary>Finds the YubiKeys that answer on the FIDO HID interface.</summary>
public static class YubicoFidoKeys
{
    /// <summary>
    /// The key to provision: the one with the expected serial, or the only one
    /// plugged in. Two keys and no serial is refused - guessing which key gets a
    /// stranger's passkey is not a choice the agent makes.
    /// </summary>
    /// <remarks>
    /// Raw FIDO HID is open only to an elevated process on Windows. The service is
    /// LocalSystem and has it; anything else gets an error that says so instead of
    /// an empty list that reads as "no key".
    /// </remarks>
    public static IFidoKey Open(long? serial)
    {
        List<IYubiKeyDevice> found;

        try
        {
            found = YubiKeyDevice.FindByTransport(Transport.HidFido).ToList();
        }
        catch (UnauthorizedAccessException e)
        {
            throw new FidoException(FidoError.Other,
                "Windows refused access to the FIDO interface. Only an elevated process may use it; "
                + "the Blinky agent service runs as LocalSystem for this reason.", e);
        }

        var chosen = serial is { } wanted
            ? found.FirstOrDefault(d => d.SerialNumber == wanted)
              ?? throw new FidoException(FidoError.Other, $"Key {wanted} is not plugged in, or its FIDO application is disabled.")
            : found.Count switch
            {
                0 => throw new FidoException(FidoError.Other, "No security key with FIDO2 is plugged in."),
                1 => found[0],
                _ => throw new FidoException(FidoError.Other,
                    $"{found.Count} security keys are plugged in and the job names none. Leave only the one to provision."),
            };

        return new YubicoFidoKey(chosen);
    }
}

/// <summary>
/// <see cref="IFidoKey"/> on Yubico's SDK. The one part of the FIDO2 path that only
/// a key on the bench can prove: every line here is unverified until it has run.
/// </summary>
/// <remarks>
/// The SDK asks for PINs through a key collector. This one never asks a person -
/// the engine has already done that, through the agent's window, labelled as the
/// FIDO2 PIN - it answers with the PIN the engine handed down, and treats a request
/// it has no answer for as a cancellation rather than a prompt nobody would see.
/// </remarks>
internal sealed class YubicoFidoKey : IFidoKey
{
    private readonly IYubiKeyDevice device;
    private readonly Fido2Session session;
    private byte[]? pin;
    private Action? touch;

    public YubicoFidoKey(IYubiKeyDevice device)
    {
        this.device = device;
        session = new Fido2Session(device) { KeyCollector = Collect };
    }

    public FidoKeyInfo Info()
    {
        // Asked of the key, not of the session: the session's copy is read once,
        // and after a PIN is set or a minimum length changed it is wrong.
        var info = session.Connection.SendCommand(new GetInfoCommand()).GetData();
        var options = info.Options ?? new Dictionary<string, bool>();
        var firmware = device.FirmwareVersion;

        return new FidoKeyInfo(
            device.SerialNumber,
            $"{firmware.Major}.{firmware.Minor}.{firmware.Patch}",
            new Guid(info.Aaguid.Span, bigEndian: true),
            info.Versions ?? [],
            SupportsPin: options.ContainsKey("clientPin"),
            PinSet: options.GetValueOrDefault("clientPin"),
            MinPinLength: info.MinimumPinLength ?? AuthenticatorInfo.DefaultMinimumPinLength,
            ForcePinChange: info.ForcePinChange ?? false,
            SupportsConfig: options.GetValueOrDefault("authnrCfg"),
            SupportsMinPinLength: options.GetValueOrDefault("setMinPINLength"),
            info.RemainingDiscoverableCredentials);
    }

    public int? PinRetries()
    {
        var response = session.Connection.SendCommand(new GetPinRetriesCommand());
        return response.Status == ResponseStatus.Success ? response.GetData().Item1 : null;
    }

    public void SetPin(string value) => Ctap(() =>
    {
        if (!session.TrySetPin(Encoding.UTF8.GetBytes(value)))
        {
            throw new FidoException(FidoError.Other, "The key already has a FIDO2 PIN.");
        }

        pin = Encoding.UTF8.GetBytes(value);
    });

    public void ChangePin(string current, string next) => Ctap(() =>
    {
        if (!session.TryChangePin(Encoding.UTF8.GetBytes(current), Encoding.UTF8.GetBytes(next)))
        {
            throw new FidoException(FidoError.PinInvalid, "The key did not accept the current FIDO2 PIN.");
        }

        pin = Encoding.UTF8.GetBytes(next);
    });

    public void VerifyPin(string value) => Ctap(() =>
    {
        if (!session.TryVerifyPin(Encoding.UTF8.GetBytes(value), PinUvAuthTokenPermissions.AuthenticatorConfiguration,
                null, out var retries, out var powerCycle))
        {
            throw powerCycle == true
                ? new FidoException(FidoError.PinAuthBlocked, "Too many wrong FIDO2 PINs in a row.")
                : retries == 0
                    ? new FidoException(FidoError.PinBlocked, "The FIDO2 PIN is blocked.")
                    : new FidoException(FidoError.PinInvalid, $"Wrong FIDO2 PIN; {retries} attempts left.");
        }

        pin = Encoding.UTF8.GetBytes(value);
    });

    public void SetMinPinLength(int length) => Ctap(() =>
    {
        if (!session.TrySetPinConfig(length, null, null))
        {
            throw new FidoException(FidoError.Unsupported, "The key would not take a minimum FIDO2 PIN length.");
        }
    });

    public void ForceChangePin() => Ctap(() =>
    {
        if (!session.TrySetPinConfig(null, null, true))
        {
            throw new FidoException(FidoError.Unsupported, "The key would not take a forced PIN change.");
        }
    });

    public void Reset() => Ctap(() =>
    {
        var response = session.Connection.SendCommand(new ResetCommand());

        if (response.Status != ResponseStatus.Success)
        {
            throw new FidoException(Map(response.CtapStatus), $"The key refused the reset: {response.StatusMessage}");
        }
    });

    public FidoMadeCredential MakeCredential(FidoCredentialRequest request, string value, Action onTouch) => Ctap(() =>
    {
        pin = Encoding.UTF8.GetBytes(value);
        touch = onTouch;

        // A token for this rpId, so the SDK does not go looking for one.
        session.VerifyPin(PinUvAuthTokenPermissions.MakeCredential, request.RpId);

        var parameters = new MakeCredentialParameters(
            new RelyingParty(request.RpId) { Name = request.RpName },
            new UserEntity(request.UserId) { Name = request.UserName, DisplayName = request.UserDisplayName })
        {
            ClientDataHash = request.ClientDataHash,
        };

        foreach (var algorithm in request.Algorithms)
        {
            parameters.AddAlgorithm("public-key", (CoseAlgorithmIdentifier)algorithm);
        }

        foreach (var excluded in request.Exclude)
        {
            parameters.ExcludeCredential(new CredentialId { Id = excluded });
        }

        parameters.AddOption("rk", request.ResidentKey);

        var info = session.AuthenticatorInfo;

        if (request.HmacSecret && info.IsExtensionSupported("hmac-secret"))
        {
            parameters.AddHmacSecretExtension(info);
        }

        if (request.CredProtect is { } policy && info.IsExtensionSupported("credProtect"))
        {
            parameters.AddCredProtectExtension(policy switch
            {
                "userVerificationOptional" => CredProtectPolicy.UserVerificationOptional,
                "userVerificationOptionalWithCredentialIDList" => CredProtectPolicy.UserVerificationOptionalWithCredentialIDList,
                "userVerificationRequired" => CredProtectPolicy.UserVerificationRequired,
                _ => throw new FidoException(FidoError.Unsupported, $"Unknown credProtect policy '{policy}'."),
            }, request.EnforceCredProtect, info);
        }

        var made = session.MakeCredential(parameters);

        return new FidoMadeCredential(
            made.AuthenticatorData.CredentialId!.Id.ToArray(),
            AttestationObjects.Build(made.Format, made.AuthenticatorData.EncodedAuthenticatorData.Span,
                made.EncodedAttestationStatement.Span));
    });

    public void Dispose()
    {
        if (pin is not null)
        {
            Array.Clear(pin);
        }

        session.Dispose();
    }

    private bool Collect(KeyEntryData entry)
    {
        switch (entry.Request)
        {
            case KeyEntryRequest.TouchRequest:
                touch?.Invoke();
                return true;
            case KeyEntryRequest.VerifyFido2Pin when pin is not null && !entry.IsRetry:
                entry.SubmitValue(pin);
                return true;
            case KeyEntryRequest.Release:
                return true;
            default:
                // Asked for something the engine did not provide, or asked again
                // after the first answer was wrong: stop rather than loop.
                return false;
        }
    }

    private static T Ctap<T>(Func<T> call)
    {
        try
        {
            return call();
        }
        catch (Fido2Exception e)
        {
            throw new FidoException(e.Status is { } s ? Map(s) : FidoError.Other, e.Message, e);
        }
    }

    private static void Ctap(Action call) => Ctap<bool>(() =>
    {
        call();
        return true;
    });

    private static FidoError Map(CtapStatus status) => status switch
    {
        CtapStatus.PinInvalid => FidoError.PinInvalid,
        CtapStatus.PinBlocked => FidoError.PinBlocked,
        CtapStatus.PinAuthInvalid => FidoError.PinAuthBlocked,
        CtapStatus.PinPolicyViolation => FidoError.PinPolicyViolation,
        CtapStatus.PinNotSet => FidoError.PinNotSet,
        CtapStatus.CredentialExcluded => FidoError.CredentialExcluded,
        CtapStatus.NotAllowed => FidoError.NotAllowed,
        CtapStatus.OperationDenied => FidoError.OperationDenied,
        CtapStatus.ActionTimeout or CtapStatus.UserActionTimeout => FidoError.ActionTimeout,
        CtapStatus.KeyStoreFull => FidoError.KeyStoreFull,
        CtapStatus.UnsupportedOption or CtapStatus.UnsupportedExtension or CtapStatus.UnsupportedAlgorithm
            => FidoError.Unsupported,
        _ => FidoError.Other,
    };
}
