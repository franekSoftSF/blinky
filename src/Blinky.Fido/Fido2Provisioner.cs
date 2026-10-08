using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Blinky.Contracts;

namespace Blinky.Fido;

/// <summary>What the engine needs from the person at the workstation.</summary>
/// <remarks>
/// Every PIN asked for here is the <b>FIDO2</b> PIN, and the implementation must
/// say so in words a person who does not know there are two will understand.
/// </remarks>
public interface IFido2Prompts
{
    /// <returns>Null when the person cancelled.</returns>
    Task<string?> AskCurrentPinAsync(int? retries, bool wrong, CancellationToken ct);

    /// <returns>Null when the person cancelled.</returns>
    Task<string?> AskNewPinAsync(int minLength, bool rejected, CancellationToken ct);

    /// <summary>
    /// The one place a provisional PIN is ever shown. Returns once the person has
    /// acknowledged it - the only copy is on their screen.
    /// </summary>
    Task ShowProvisionalPinAsync(string pin, CancellationToken ct);

    Task TouchAsync(CancellationToken ct);

    Task StatusAsync(string message, CancellationToken ct);
}

/// <summary>The two calls the engine makes to the API.</summary>
public interface IFido2Backend
{
    Task<Fido2CeremonyRequest> ReadyAsync(Fido2Ready ready, CancellationToken ct);

    Task<Fido2Registered> ResultAsync(Fido2CeremonyResult result, CancellationToken ct);
}

/// <summary>How a provisioning ended, with nothing in it that is a PIN.</summary>
public sealed record Fido2Outcome(
    bool Registered,
    string? MethodId,
    long? TokenSerial,
    string KeyName,
    bool PinSetByAgent,
    bool ForcedPinChange,
    IReadOnlyList<string> Warnings);

/// <summary>
/// Gets a key ready, runs one WebAuthn ceremony on it for a provider it does not
/// know, and finishes the key once the provider has said yes.
/// </summary>
/// <remarks>
/// <para>
/// A port of KeyEnroll's <c>Enroller</c>, with the provider calls taken out: here
/// they are two requests to the API, which makes them. The order is KeyEnroll's,
/// and two parts of it are the reason brief 12 was corrected - the minimum PIN
/// length before the ceremony, the forced PIN change only after the provider has
/// accepted the credential. A key with a pending forced change issues no PIN
/// token, so the other order fails the ceremony on the PIN just set.
/// </para>
/// <para>
/// The provider is an opaque tag. Nothing below reads it; a test runs the same key
/// under two tags and compares every call.
/// </para>
/// </remarks>
public sealed class Fido2Provisioner(IFido2Prompts prompts, IFido2Backend backend, TimeProvider? time = null)
{
    private readonly TimeProvider clock = time ?? TimeProvider.System;

    public async Task<Fido2Outcome> RunAsync(IFidoKey key, Guid jobId, int attempt, long? expectedSerial,
        Fido2Provisioning provisioning, CancellationToken ct)
    {
        var info = key.Info();
        var policy = provisioning.Pin;
        var warnings = new List<string>();

        if (expectedSerial is { } wanted && info.Serial is { } found && wanted != found)
        {
            throw new FidoException(FidoError.Other, $"The job is for key {wanted}, and key {found} is plugged in.");
        }

        if (!info.SupportsPin)
        {
            throw new FidoException(FidoError.Unsupported, "This key has no FIDO2 PIN, so it cannot hold a passkey that needs one.");
        }

        if (policy.MinPinLength > info.MinPinLength && !info.CanForcePinChange)
        {
            // Not quietly weaker than asked: a key that cannot be told the minimum
            // would accept a shorter PIN from its holder the first time they change it.
            throw new FidoException(FidoError.Unsupported,
                $"The policy needs a FIDO2 PIN of at least {policy.MinPinLength}, and this key cannot be told to "
                + "enforce one (it needs CTAP 2.1, firmware 5.5 or later).");
        }

        if (policy.ForceChangePin && !info.CanForcePinChange)
        {
            if (policy.Mode is Fido2PinMode.ProvisionalRandom)
            {
                // The fallback the roadmap names: a PIN nobody would ever change is
                // worse than one the operator chose with the holder present.
                policy = policy with { Mode = Fido2PinMode.OperatorSets };
                warnings.Add("This key cannot force a PIN change, so the FIDO2 PIN is set by the operator instead of generated.");
                await prompts.StatusAsync(warnings[^1], ct);
            }
            else
            {
                warnings.Add("This key cannot force a PIN change; the holder is not made to change it.");
            }
        }

        var (pin, pinSet) = await PreparePinAsync(key, info, policy, ct);

        info = key.Info();

        if (policy.MinPinLength > info.MinPinLength)
        {
            await prompts.StatusAsync($"Setting the minimum FIDO2 PIN length to {policy.MinPinLength}…", ct);
            key.SetMinPinLength(policy.MinPinLength);
            info = key.Info();
        }

        var keyName = provisioning.AppendSerial
            ? Fido2KeyName.Compose(provisioning.KeyName, info.Serial, null)
            : provisioning.KeyName;

        await prompts.StatusAsync("Asking for a challenge…", ct);

        var ceremony = await backend.ReadyAsync(new Fido2Ready(
            Protocol.Fido2SchemaVersion, jobId, attempt, info.Serial, info.Firmware, info.Aaguid, info.Versions,
            info.PinSet, key.PinRetries(), info.RemainingDiscoverableCredentials,
            info.CanForcePinChange, info.CanForcePinChange), ct);

        if (ceremony.DeadlineAt <= clock.GetUtcNow())
        {
            throw new FidoException(FidoError.Other, "The challenge had expired before it arrived.");
        }

        var clientDataJson = ClientDataJson(ceremony.Challenge, ceremony.Origin);
        var made = MakeCredential(key, ceremony, clientDataJson, pin, ct);

        await prompts.StatusAsync("Registering the passkey with the provider…", ct);

        var registered = await backend.ResultAsync(new Fido2CeremonyResult(
            Protocol.Fido2SchemaVersion, jobId, ceremony.CeremonyId, info.Serial, info.Aaguid,
            Base64Url.EncodeToString(made.CredentialId),
            Base64Url.EncodeToString(clientDataJson),
            Base64Url.EncodeToString(made.AttestationObject),
            keyName, pinSet), ct);

        if (!registered.Registered)
        {
            // No forced change on a key whose credential nobody accepted: the PIN
            // stays usable for the retry, which has to verify it.
            return new Fido2Outcome(false, null, info.Serial, keyName, pinSet, false,
                [.. warnings, $"The provider refused the passkey: {registered.Detail}"]);
        }

        var forced = false;

        if (policy.ForceChangePin && info.CanForcePinChange)
        {
            await prompts.StatusAsync("Making the holder change the FIDO2 PIN on first use…", ct);

            try
            {
                key.ForceChangePin();
                forced = true;
            }
            catch (FidoException e)
            {
                // The passkey is registered and works. Failing the job now would
                // say otherwise, so this is a warning on a success.
                warnings.Add($"The passkey is registered, but forcing a PIN change failed: {e.Message}");
            }
        }

        return new Fido2Outcome(true, registered.MethodId, info.Serial, keyName, pinSet, forced, warnings);
    }

    /// <summary>
    /// The bytes the key signs over, built once and sent as they are. The challenge
    /// is written exactly as the API sent it - the provider compares text, and a
    /// re-encoding that changed padding or alphabet would fail there with nothing
    /// to say why.
    /// </summary>
    public static byte[] ClientDataJson(string challenge, string origin) =>
        Encoding.UTF8.GetBytes(
            "{\"type\":\"webauthn.create\",\"challenge\":" + JsonSerializer.Serialize(challenge)
            + ",\"origin\":" + JsonSerializer.Serialize(origin) + ",\"crossOrigin\":false}");

    private async Task<(string Pin, bool Set)> PreparePinAsync(IFidoKey key, FidoKeyInfo info,
        Fido2PinPolicy policy, CancellationToken ct)
    {
        var minLength = Math.Max(policy.MinPinLength, info.MinPinLength);

        if (!info.PinSet)
        {
            await prompts.StatusAsync("Setting the FIDO2 PIN…", ct);
            var set = await SetNewPinAsync(key.SetPin, policy, minLength, ct);
            key.VerifyPin(set);
            return (set, true);
        }

        var current = await VerifyCurrentAsync(key, info, ct);

        if (policy.Mode is Fido2PinMode.ProvisionalRandom || info.ForcePinChange)
        {
            await prompts.StatusAsync("Changing the FIDO2 PIN…", ct);
            var changed = await SetNewPinAsync(next => key.ChangePin(current, next), policy, minLength, ct);
            key.VerifyPin(changed);
            return (changed, true);
        }

        if (current.Length < policy.MinPinLength)
        {
            throw new FidoException(FidoError.PinPolicyViolation,
                $"The key's FIDO2 PIN is shorter than the policy's {policy.MinPinLength}. "
                + "Ask for a generated PIN, or reset the key.");
        }

        return (current, false);
    }

    /// <summary>Chooses a PIN and applies it, choosing again when the key's own policy refuses it.</summary>
    private async Task<string> SetNewPinAsync(Action<string> apply, Fido2PinPolicy policy, int minLength,
        CancellationToken ct)
    {
        var rejected = false;

        for (var tries = 0; tries < 10; tries++)
        {
            var generated = policy.Mode is Fido2PinMode.ProvisionalRandom;
            var pin = generated
                ? Fido2Pin.Generate(Math.Max(minLength, 6))
                : await AskNewAsync(minLength, rejected, ct);

            try
            {
                apply(pin);
            }
            catch (FidoException e) when (e.Error is FidoError.PinPolicyViolation)
            {
                rejected = true;
                continue;
            }

            if (generated)
            {
                // Before anything else can fail: a key left holding a PIN nobody
                // saw is a key only a reset can recover.
                await prompts.ShowProvisionalPinAsync(pin, ct);
            }

            return pin;
        }

        throw new FidoException(FidoError.PinPolicyViolation, "The key refused every FIDO2 PIN offered to it.");
    }

    private async Task<string> AskNewAsync(int minLength, bool rejected, CancellationToken ct)
    {
        while (true)
        {
            var pin = await prompts.AskNewPinAsync(minLength, rejected, ct)
                      ?? throw new OperationCanceledException("The FIDO2 PIN was not entered.");

            if (pin.Length >= minLength)
            {
                return pin;
            }

            rejected = true;
        }
    }

    private async Task<string> VerifyCurrentAsync(IFidoKey key, FidoKeyInfo info, CancellationToken ct)
    {
        var wrong = false;

        while (true)
        {
            var pin = await prompts.AskCurrentPinAsync(key.PinRetries(), wrong, ct)
                      ?? throw new OperationCanceledException("The FIDO2 PIN was not entered.");

            if (info.ForcePinChange)
            {
                // No token is issued until the PIN is changed; the change itself
                // proves the current one.
                return pin;
            }

            try
            {
                key.VerifyPin(pin);
                return pin;
            }
            catch (FidoException e) when (e.Error is FidoError.PinInvalid)
            {
                wrong = true;
            }
            catch (FidoException e) when (e.Error is FidoError.PinAuthBlocked)
            {
                throw new FidoException(e.Error, "Too many wrong FIDO2 PINs in a row. Pull the key out, put it back, and try again.", e);
            }
            catch (FidoException e) when (e.Error is FidoError.PinBlocked)
            {
                throw new FidoException(e.Error, "The FIDO2 PIN is blocked. Only a FIDO reset brings the key back, and it erases every passkey on it.", e);
            }
        }
    }

    private FidoMadeCredential MakeCredential(IFidoKey key, Fido2CeremonyRequest ceremony, byte[] clientDataJson,
        string pin, CancellationToken ct)
    {
        var request = new FidoCredentialRequest(
            SHA256.HashData(clientDataJson),
            ceremony.RpId,
            ceremony.RpName,
            Base64Url.DecodeFromChars(ceremony.UserHandle),
            ceremony.UserName,
            ceremony.UserDisplayName,
            ceremony.Algorithms,
            ceremony.ExcludeCredentials.Select(c => Base64Url.DecodeFromChars(c)).ToList(),
            ResidentKey: ceremony.ResidentKey is "required" or "preferred",
            UserVerification: ceremony.UserVerification is not "discouraged",
            ceremony.HmacCreateSecret,
            ceremony.CredentialProtectionPolicy,
            ceremony.EnforceCredentialProtectionPolicy);

        try
        {
            return key.MakeCredential(request, pin, () => prompts.TouchAsync(ct).GetAwaiter().GetResult());
        }
        catch (FidoException e) when (e.Error is FidoError.CredentialExcluded)
        {
            throw new FidoException(e.Error, "This key already holds a passkey for this user at this provider.", e);
        }
        catch (FidoException e) when (e.Error is FidoError.ActionTimeout or FidoError.OperationDenied or FidoError.NotAllowed)
        {
            throw new FidoException(e.Error, "The key was not touched in time.", e);
        }
        catch (FidoException e) when (e.Error is FidoError.KeyStoreFull)
        {
            throw new FidoException(e.Error, "The key has no room for another passkey.", e);
        }
    }
}
