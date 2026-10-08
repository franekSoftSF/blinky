namespace Blinky.Passkeys;

/// <summary>A user as the provider knows them.</summary>
/// <param name="Id">The provider's id - an Entra object id, an Okta user id.</param>
/// <param name="Login">UPN or Okta login, kept as a snapshot for the audit trail.</param>
public sealed record PasskeyUser(string Id, string Login, string DisplayName = "", string Email = "");

/// <summary>
/// WebAuthn creation options, normalised: Graph's and Okta's field names, base64
/// flavours and missing defaults are gone by the time a value lands here.
/// </summary>
/// <remarks>
/// Binary values are bytes, not text. The challenge is the provider's bytes; the
/// agent writes them into <c>clientDataJSON</c> as unpadded base64url, which is
/// what WebAuthn defines and what the provider compares against - not as whatever
/// spelling the provider happened to send them in.
/// </remarks>
/// <param name="RpId">From the provider's answer, never from a constant.</param>
/// <param name="Origin">
/// What <c>clientDataJSON.origin</c> must say. Derived per provider; for both it
/// is an https origin whose host is the rpId or under it.
/// </param>
/// <param name="Algorithms">COSE algorithm ids in the provider's order of preference.</param>
/// <param name="ResidentKey"><c>required</c>, <c>preferred</c> or <c>discouraged</c>.</param>
/// <param name="UserVerification"><c>required</c>, <c>preferred</c> or <c>discouraged</c>.</param>
/// <param name="Attestation"><c>none</c>, <c>indirect</c>, <c>direct</c> or <c>enterprise</c>.</param>
/// <param name="Deadline">When the challenge stops being accepted.</param>
public sealed record PasskeyCreationOptions(
    string RpId,
    string RpName,
    string Origin,
    byte[] Challenge,
    byte[] UserHandle,
    string UserName,
    string UserDisplayName,
    IReadOnlyList<int> Algorithms,
    IReadOnlyList<byte[]> ExcludeCredentials,
    string ResidentKey,
    string UserVerification,
    string? AuthenticatorAttachment,
    string Attestation,
    PasskeyExtensions Extensions,
    DateTimeOffset Deadline);

/// <summary>
/// The extensions a provider asked for. Only the ones that change what the key
/// stores are kept; WebAuthn lets a client ignore the rest, and so does Blinky.
/// </summary>
/// <param name="CredentialProtectionPolicy">
/// Graph spells credProtect this way: <c>userVerificationOptional</c>,
/// <c>userVerificationOptionalWithCredentialIDList</c>, <c>userVerificationRequired</c>.
/// </param>
public sealed record PasskeyExtensions(
    bool HmacCreateSecret = false,
    string? CredentialProtectionPolicy = null,
    bool EnforceCredentialProtectionPolicy = false)
{
    public static readonly PasskeyExtensions None = new();
}

/// <summary>A ceremony the provider has started and is waiting to see finished.</summary>
/// <param name="ProviderReference">
/// What the provider needs to finish or clean up - Okta's factor id. Plain text so
/// a job can carry it across an API restart.
/// </param>
public sealed record PendingRegistration(
    PasskeyUser User,
    PasskeyCreationOptions Options,
    string? ProviderReference)
{
    public RegistrationHandle Handle => new(User, ProviderReference);
}

/// <summary>
/// All a provider needs to finish or clean up a ceremony - not the options. The
/// options go to the key; this is what the API keeps, and what it can rebuild
/// from a database row after a restart.
/// </summary>
public sealed record RegistrationHandle(PasskeyUser User, string? ProviderReference);

/// <summary>What the authenticator produced, exactly as it produced it.</summary>
/// <remarks>
/// Never re-encoded on the way through: the attestation signature covers these
/// bytes, and a CBOR library that canonicalises a map on the way past turns a
/// valid attestation into one that fails at the provider with no useful message.
/// </remarks>
public sealed record AttestationResponse(
    byte[] CredentialId,
    byte[] ClientDataJson,
    byte[] AttestationObject);

/// <param name="MethodId">Entra's fido2Method id, Okta's factor id.</param>
public sealed record RegisteredPasskey(string MethodId, DateTimeOffset? Created);

/// <summary>A passkey as the provider lists it, for drift and revocation.</summary>
/// <param name="Status">
/// Okta's factor status. <c>PENDING_ACTIVATION</c> here is a ceremony somebody
/// started and nobody cleaned up.
/// </param>
public sealed record ProviderPasskey(
    string MethodId,
    string DisplayName,
    DateTimeOffset? Created,
    Guid? Aaguid = null,
    string? Model = null,
    string? Status = null);
