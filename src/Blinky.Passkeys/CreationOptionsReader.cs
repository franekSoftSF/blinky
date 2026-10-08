using System.Text.Json;

namespace Blinky.Passkeys;

/// <summary>
/// A <c>PublicKeyCredentialCreationOptions</c> in its JSON form, as Graph's
/// <c>publicKey</c> and Okta's <c>activation</c> both nearly are.
/// </summary>
internal static class CreationOptionsReader
{
    /// <param name="rpIdFallback">Okta may leave <c>rp.id</c> out; WebAuthn then means the origin's host.</param>
    /// <param name="userHandle">How this provider spells the user handle.</param>
    /// <param name="origin">Given the rpId the provider settled on.</param>
    public static PasskeyCreationOptions Read(
        JsonElement options,
        string label,
        string? rpIdFallback,
        Func<JsonElement, byte[]> userHandle,
        Func<string, string> origin,
        DateTimeOffset deadline)
    {
        var rp = Json.Required(options, "rp", label);
        var rpId = Json.Text(rp, "id") is { Length: > 0 } id ? id
            : rpIdFallback ?? throw new PasskeyDirectoryException($"{label}: the options name no relying party.");

        var user = Json.Required(options, "user", label);
        var challenge = WireBinary.Read(Json.Required(options, "challenge", label));

        // No minimum length beyond empty. WebAuthn asks a relying party for sixteen
        // bytes, but Okta's are twenty base64url characters - fifteen bytes - and
        // refusing them here would be Blinky enforcing the spec on somebody else.
        if (challenge.Length == 0)
        {
            throw new PasskeyDirectoryException($"{label}: the challenge is empty.");
        }

        var algorithms = Json.Child(options, "pubKeyCredParams") is { ValueKind: JsonValueKind.Array } p
            ? p.EnumerateArray()
                .Where(x => Json.Text(x, "type") is null or "public-key")
                .Select(x => Json.Required(x, "alg", label).GetInt32())
                .ToList()
            : [];

        if (algorithms.Count == 0)
        {
            throw new PasskeyDirectoryException($"{label}: the options allow no algorithm.");
        }

        var exclude = Json.Child(options, "excludeCredentials") is { ValueKind: JsonValueKind.Array } x2
            ? x2.EnumerateArray().Select(c => WireBinary.Read(Json.Required(c, "id", label))).ToList()
            : [];

        var selection = Json.Child(options, "authenticatorSelection");
        var residentKey = selection is { } s1 && Json.Text(s1, "residentKey") is { } rk ? rk
            : selection is { } s2 && Json.Flag(s2, "requireResidentKey") == true ? "required"
            : "discouraged";
        var userVerification = selection is { } s3 && Json.Text(s3, "userVerification") is { } uv ? uv : "preferred";
        var attachment = selection is { } s4 ? Json.Text(s4, "authenticatorAttachment") : null;

        return new PasskeyCreationOptions(
            RpId: rpId,
            RpName: Json.Text(rp, "name") ?? rpId,
            Origin: origin(rpId),
            Challenge: challenge,
            UserHandle: userHandle(Json.Required(user, "id", label)),
            UserName: Json.Text(user, "name") ?? "",
            UserDisplayName: Json.Text(user, "displayName") ?? "",
            Algorithms: algorithms,
            ExcludeCredentials: exclude,
            ResidentKey: residentKey,
            UserVerification: userVerification,
            AuthenticatorAttachment: attachment,
            Attestation: Json.Text(options, "attestation") ?? "none",
            Extensions: ReadExtensions(Json.Child(options, "extensions")),
            Deadline: deadline);
    }

    private static PasskeyExtensions ReadExtensions(JsonElement? extensions) =>
        extensions is not { ValueKind: JsonValueKind.Object } e
            ? PasskeyExtensions.None
            : new PasskeyExtensions(
                HmacCreateSecret: Json.Flag(e, "hmacCreateSecret") == true,
                CredentialProtectionPolicy: Json.Text(e, "credentialProtectionPolicy"),
                EnforceCredentialProtectionPolicy: Json.Flag(e, "enforceCredentialProtectionPolicy") == true);
}
