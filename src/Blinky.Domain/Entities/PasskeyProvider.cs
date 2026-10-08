using System.Text.Json.Serialization;

namespace Blinky.Domain.Entities;

/// <summary>
/// An identity provider passkeys are registered with, as an administrator
/// configured it in the console.
/// </summary>
/// <remarks>
/// <para>
/// In the database and not in <c>.env</c>: configuration that only somebody with a
/// shell on the server can change is configuration only its author changes, and a
/// client secret in an environment variable is in every <c>docker inspect</c>.
/// Configuration, so it has full CRUD (CLAUDE.md) - but the name is fixed once
/// created, because passkey rows refer to the provider by it, and a provider with
/// registered passkeys is disabled rather than deleted.
/// </para>
/// <para>
/// The credential is sealed: AES-GCM under a key derived from the PUK KEK in a
/// domain of its own and bound to this row's id, the way an escrowed PUK is bound
/// to its token. The console is told whether one is set and what identifies it -
/// a thumbprint, a key id - and never the thing itself.
/// </para>
/// </remarks>
public class PasskeyProvider
{
    public virtual Guid Id { get; protected set; }

    /// <summary>Unique, and fixed once created: passkey rows name their provider by it.</summary>
    public virtual string Name { get; set; } = string.Empty;

    public virtual PasskeyProviderKind Kind { get; set; }

    public virtual bool IsEnabled { get; set; } = true;

    /// <summary>Entra: the directory (tenant) id.</summary>
    public virtual string? TenantId { get; set; }

    /// <summary>Entra's application id; Okta's service-app client id.</summary>
    public virtual string? ClientId { get; set; }

    /// <summary>Okta: the URL users sign in at, custom domain included.</summary>
    public virtual string? OrgUrl { get; set; }

    /// <summary>Okta: the <c>kid</c> of the key, once the app has more than one.</summary>
    public virtual string? KeyId { get; set; }

    /// <summary>Entra: changed only for a national cloud.</summary>
    public virtual string? Authority { get; set; }

    /// <summary>Entra: changed only for a national cloud.</summary>
    public virtual string? GraphUrl { get; set; }

    public virtual int ChallengeMinutes { get; set; } = 10;

    public virtual PasskeyProviderCredential? CredentialKind { get; set; }

    public virtual byte[]? SecretCiphertext { get; set; }

    public virtual byte[]? SecretNonce { get; set; }

    public virtual byte[]? SecretTag { get; set; }

    /// <summary>Which KEK generation sealed it, read back rather than assumed.</summary>
    public virtual int? SecretKeyVersion { get; set; }

    /// <summary>
    /// The public half, for the administrator to give the provider: a certificate
    /// for Entra, a JWK for Okta. Not a secret, and shown in the console.
    /// </summary>
    public virtual string? PublicMaterial { get; set; }

    /// <summary>What identifies the credential without revealing it: a thumbprint, a kid.</summary>
    public virtual string? CredentialHint { get; set; }

    public virtual DateTime? CredentialExpiresAt { get; set; }

    public virtual DateTime? CredentialSetAt { get; set; }

    public virtual string? CredentialSetBy { get; set; }

    public virtual DateTime CreatedAt { get; set; }

    public virtual DateTime UpdatedAt { get; set; }
}

/// <summary>By name on the wire: the console sends and compares "Entra", never 0.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<PasskeyProviderKind>))]
public enum PasskeyProviderKind
{
    Entra,
    Okta,
}

/// <summary>How Blinky proves to the provider that it is the registered application.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<PasskeyProviderCredential>))]
public enum PasskeyProviderCredential
{
    /// <summary>Entra: a certificate and its RSA key. Preferred.</summary>
    Certificate,

    /// <summary>Entra: a client secret. For a lab.</summary>
    ClientSecret,

    /// <summary>Okta: a service app's private key, <c>private_key_jwt</c>. Preferred.</summary>
    PrivateKey,

    /// <summary>Okta: an SSWS API token. For a lab.</summary>
    ApiToken,
}
