namespace Blinky.Passkeys;

/// <summary>
/// An identity provider that accepts a WebAuthn credential created on somebody
/// else's behalf. Entra and Okta today; the shape mirrors <c>Blinky.Pki</c>.
/// </summary>
/// <remarks>
/// <para>
/// Blinky does not mint this credential. The key creates it in a ceremony whose
/// relying party is the provider, so everything here is the provider's half of
/// that ceremony: hand out options, take back the attestation, and later list or
/// delete what was registered. See docs/12-passkey-provisioning-brief.md.
/// </para>
/// <para>
/// Begin and complete are separate calls because the ceremony between them runs
/// on a workstation, through a job, and can take as long as a person takes to
/// find the key. A begin that is never completed must be cancelled: Okta keeps a
/// pending factor for it, and a second attempt for the same user fails against
/// that leftover rather than against anything the operator can see.
/// </para>
/// </remarks>
public interface IPasskeyDirectory
{
    /// <summary>The configured instance this speaks for.</summary>
    string Name { get; }

    PasskeyCapabilities Capabilities { get; }

    /// <summary>
    /// Exact lookup by the identifier Blinky knows a cardholder by - a UPN, a
    /// login, an e-mail or the provider's own id. Null when nothing matches or
    /// the match is ambiguous; a permission error is thrown, not hidden as null.
    /// </summary>
    Task<PasskeyUser?> FindUserAsync(string identifier, CancellationToken ct = default);

    /// <summary>
    /// Asks the provider for creation options. Not free of side effects on every
    /// provider - see the remarks on the interface - so call it only once the key
    /// is in the reader, and call <see cref="CancelRegistrationAsync"/> if the
    /// ceremony does not complete.
    /// </summary>
    Task<PendingRegistration> BeginRegistrationAsync(PasskeyUser user, CancellationToken ct = default);

    Task<RegisteredPasskey> CompleteRegistrationAsync(PendingRegistration pending,
        AttestationResponse response, string displayName, CancellationToken ct = default);

    /// <summary>Removes whatever the provider kept for a ceremony that did not finish.</summary>
    Task CancelRegistrationAsync(PendingRegistration pending, CancellationToken ct = default);

    Task<IReadOnlyList<ProviderPasskey>> ListAsync(PasskeyUser user, CancellationToken ct = default);

    Task DeleteAsync(PasskeyUser user, string methodId, CancellationToken ct = default);
}

/// <summary>What a provider can do, so the console adapts instead of failing late.</summary>
/// <param name="SupportsRegistration">
/// False for a provider that is configured only to be explained - Google today,
/// which accepts no attestation on a user's behalf.
/// </param>
/// <param name="PrepareOnly">
/// The key can be prepared (PIN, policy) but registration is left to the user.
/// Present from the first commit so that answering the Google question later does
/// not reshape this interface.
/// </param>
/// <param name="PinDeliveryByProvider">The provider tells the user the PIN itself.</param>
/// <param name="AcceptsDisplayName">Whether the name Blinky gives the key is kept.</param>
/// <param name="MaxDisplayNameLength">Longer names are refused, not truncated, by the provider.</param>
public sealed record PasskeyCapabilities(
    bool SupportsRegistration,
    bool PrepareOnly,
    bool PinDeliveryByProvider,
    bool AcceptsDisplayName,
    int? MaxDisplayNameLength);

/// <summary>The provider refused, or could not be reached.</summary>
/// <param name="Status">The HTTP status, when there was one.</param>
public class PasskeyDirectoryException(string message, int? status = null, Exception? inner = null)
    : Exception(message, inner)
{
    public int? Status { get; } = status;
}

/// <summary>
/// Blinky could not obtain a token. Separate because it is a configuration fault
/// - a certificate, a secret, a consent - and never something to retry.
/// </summary>
public sealed class PasskeyAuthorizationException(string message, Exception? inner = null)
    : PasskeyDirectoryException(message, null, inner);
