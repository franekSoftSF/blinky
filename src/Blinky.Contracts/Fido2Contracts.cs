using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;

namespace Blinky.Contracts;

/// <summary>Who chooses the FIDO2 PIN a provisioned key leaves with.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<Fido2PinMode>))]
public enum Fido2PinMode
{
    /// <summary>The person at the workstation types it, in the agent's window.</summary>
    OperatorSets,

    /// <summary>
    /// The agent generates it and shows it once, on the workstation. It is in no
    /// message in this file, which is how "shown once, stored nowhere" is kept
    /// rather than promised: what is not on the wire cannot reach a column.
    /// </summary>
    ProvisionalRandom,

    /// <summary>The provider tells the user. Okta's Preregistration API only - 0073b.</summary>
    ProviderDelivers,
}

/// <summary>What the key must look like before the ceremony, and after it.</summary>
/// <param name="MinPinLength">
/// Applied with <c>setMinPINLength</c> where the key has CTAP 2.1; where it has
/// not, a key whose own minimum is lower is refused rather than left weaker than
/// the policy says.
/// </param>
/// <param name="ForceChangePin">
/// Set <b>after</b> the provider has accepted the registration. A key with a
/// pending forced change issues no PIN token, so setting it before the ceremony
/// would fail the ceremony on the PIN that was just set - brief 12 said otherwise
/// until KeyEnroll showed the order.
/// </param>
public sealed record Fido2PinPolicy(Fido2PinMode Mode, int MinPinLength, bool ForceChangePin);

/// <summary>
/// The prepare message: the one step of a <see cref="JobType.ProvisionFido2Credential"/>
/// job, and the arguments it carries.
/// </summary>
/// <remarks>
/// Only what the agent needs to get the key ready. The provider is an opaque tag
/// for the audit trail and for the window to name; the agent behaves identically
/// for every value of it, and a test holds it to that.
/// </remarks>
/// <param name="Directory">The configured provider instance, by name. Opaque to the agent.</param>
/// <param name="Holder">Whose key it will be, for the window: "a security key for Jan Kowalski".</param>
/// <param name="KeyName">The base of the name the key is registered under.</param>
/// <param name="AppendSerial">Whether the agent adds the serial it read to that name.</param>
public sealed record Fido2Provisioning(
    string Directory,
    string Holder,
    Fido2PinPolicy Pin,
    string KeyName,
    bool AppendSerial)
{
    public const string Op = "ProvisionFido2Credential";

    public JobStep ToStep() => new(Op, new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["directory"] = Directory,
        ["holder"] = Holder,
        ["pinMode"] = Pin.Mode.ToString(),
        ["minPinLength"] = Pin.MinPinLength.ToString(CultureInfo.InvariantCulture),
        ["forceChangePin"] = Pin.ForceChangePin ? "true" : "false",
        ["keyName"] = KeyName,
        ["appendSerial"] = AppendSerial ? "true" : "false",
    });

    /// <summary>
    /// Reads a step back, refusing anything it does not understand. A PIN mode
    /// from a newer server is not quietly read as the default.
    /// </summary>
    public static Fido2Provisioning FromStep(JobStep step)
    {
        if (step.Op != Op)
        {
            throw new ArgumentException($"Step {step.Op} is not {Op}.", nameof(step));
        }

        string Required(string name) => step.Argument(name)
            ?? throw new FormatException($"{Op} has no '{name}'.");

        if (!Enum.TryParse<Fido2PinMode>(Required("pinMode"), ignoreCase: false, out var mode)
            || !Enum.IsDefined(mode))
        {
            throw new FormatException($"{Op}: PIN mode '{step.Argument("pinMode")}' is not one this agent knows.");
        }

        if (!int.TryParse(Required("minPinLength"), NumberStyles.None, CultureInfo.InvariantCulture, out var min)
            || min is < 4 or > 63)
        {
            // CTAP's own bounds: four code points at least, 63 bytes at most.
            throw new FormatException($"{Op}: a minimum PIN length of '{step.Argument("minPinLength")}' is not one.");
        }

        return new Fido2Provisioning(
            Required("directory"),
            step.Argument("holder") ?? "",
            new Fido2PinPolicy(mode, min, Required("forceChangePin") == "true"),
            step.Argument("keyName") ?? "",
            step.Argument("appendSerial") == "true");
    }
}

/// <summary>
/// The ready message: the key is in the reader, prepared, and the agent wants a
/// challenge. Agent to API, <c>POST /api/jobs/{id}/fido2/ready</c>; the answer is
/// a <see cref="Fido2CeremonyRequest"/>.
/// </summary>
/// <remarks>
/// The challenge is asked for only now, never with the job, because its lifetime
/// is the provider's and it starts running when the provider is asked. A job that
/// waited in a queue with a challenge in it would arrive with a dead one.
/// </remarks>
/// <param name="TokenSerial">Null for a key that will not say - not a YubiKey, or an NFC read.</param>
/// <param name="PinRetries">The FIDO2 PIN's counter. Never the PIV PIN's; the two are separate and stay so.</param>
/// <param name="DiscoverableCredentialsRemaining">Null when the key does not report it.</param>
public sealed record Fido2Ready(
    int SchemaVersion,
    Guid JobId,
    int Attempt,
    long? TokenSerial,
    string? Firmware,
    Guid Aaguid,
    IReadOnlyList<string> CtapVersions,
    bool PinSet,
    int? PinRetries,
    int? DiscoverableCredentialsRemaining,
    bool SupportsForceChangePin,
    bool SupportsMinPinLength);

/// <summary>
/// The ceremony message: the provider's creation options, normalised. API to
/// agent, as the answer to <see cref="Fido2Ready"/>.
/// </summary>
/// <remarks>
/// <para>
/// Binary values are unpadded base64url, the challenge exactly as the agent must
/// write it into <c>clientDataJSON</c>. rpId and origin are the provider's, carried
/// here because the agent must never know them any other way.
/// </para>
/// <para>
/// <see cref="CeremonyId"/> is derived from the job and the challenge, so the same
/// challenge sent twice - a retried request, an API that restarted between - is
/// the same ceremony, and an agent that already ran it answers with the result it
/// has instead of creating a second credential on the key.
/// </para>
/// </remarks>
public sealed record Fido2CeremonyRequest(
    Guid CeremonyId,
    Guid JobId,
    string Directory,
    string RpId,
    string RpName,
    string Origin,
    string Challenge,
    string UserHandle,
    string UserName,
    string UserDisplayName,
    IReadOnlyList<int> Algorithms,
    IReadOnlyList<string> ExcludeCredentials,
    string ResidentKey,
    string UserVerification,
    string? AuthenticatorAttachment,
    string Attestation,
    bool HmacCreateSecret,
    string? CredentialProtectionPolicy,
    bool EnforceCredentialProtectionPolicy,
    DateTimeOffset DeadlineAt)
{
    /// <summary>The same job and the same challenge are the same ceremony.</summary>
    public static Guid IdFor(Guid jobId, string challenge)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes($"{jobId:N}:{challenge}"));
        return new Guid(hash.AsSpan(0, 16));
    }
}

/// <summary>
/// The result message: what the key produced. Agent to API,
/// <c>POST /api/jobs/{id}/fido2/result</c>; the answer is <see cref="Fido2Registered"/>.
/// </summary>
/// <remarks>
/// No PIN, in any mode. Whether the agent set one is a fact worth recording;
/// what it was is not, and the type has nowhere to put it.
/// </remarks>
/// <param name="CredentialId">Unpadded base64url.</param>
/// <param name="ClientDataJson">The bytes the agent hashed, unpadded base64url.</param>
/// <param name="AttestationObject">As the key produced it, never re-encoded. Unpadded base64url.</param>
/// <param name="KeyName">The name the agent composed, serial included when asked for.</param>
public sealed record Fido2CeremonyResult(
    int SchemaVersion,
    Guid JobId,
    Guid CeremonyId,
    long? TokenSerial,
    Guid Aaguid,
    string CredentialId,
    string ClientDataJson,
    string AttestationObject,
    string KeyName,
    bool PinSetByAgent);

/// <summary>
/// The provider's verdict on the result, and whether the agent may now finish
/// the key - <c>forceChangePin</c>, which must wait for exactly this.
/// </summary>
/// <param name="MethodId">The provider's id for the new credential, for the audit trail.</param>
/// <param name="Detail">Why it was refused, in the provider's words where it gave any.</param>
public sealed record Fido2Registered(
    Guid CeremonyId,
    bool Registered,
    string? MethodId,
    string? Detail);
