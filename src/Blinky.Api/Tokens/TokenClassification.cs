using Blinky.Contracts;
using Blinky.Domain;

namespace Blinky.Api.Tokens;

/// <summary>
/// What an agent's facts mean. Kept apart from the persistence so the rules can
/// be read, and tested, without a database in the way.
/// </summary>
public static class TokenClassification
{
    public static CredentialSecretState Pin(CredentialReport credential) => credential switch
    {
        { IsBlocked: true } => CredentialSecretState.Blocked,
        { IsDefault: true } => CredentialSecretState.Default,
        { IsDefault: false } => CredentialSecretState.Set,
        _ => CredentialSecretState.Unknown,
    };

    /// <summary>
    /// The rule the whole personalisation policy rests on. Zero total retries
    /// means there is no PUK at all - which on a Bio Multi-protocol is the
    /// factory state and fine, and on anything else means somebody removed the
    /// recovery path and nobody recorded why. The card cannot tell the two
    /// apart; the presence of biometrics can.
    /// </summary>
    public static CredentialSecretState Puk(CredentialReport puk,
        BiometricReport? biometrics)
    {
        if (puk.TotalRetries == 0)
        {
            return biometrics is not null
                ? CredentialSecretState.NotApplicable
                : CredentialSecretState.Disabled;
        }

        return Pin(puk);
    }

    public static BiometricState Biometrics(BiometricReport? biometrics) => biometrics switch
    {
        null => BiometricState.NotSupported,
        { FingerprintsEnrolled: false } => BiometricState.NotEnrolled,
        { AttemptsRemaining: 0 } => BiometricState.Blocked,
        _ => BiometricState.Enrolled,
    };

    /// <summary>
    /// A management key that is neither the factory value nor a version we
    /// recorded makes the token unmanageable, and an operator has to see that
    /// in a list rather than discover it in a failed job.
    /// </summary>
    public static ManagementKeyState ManagementKey(ManagementKeyReport? key, int recordedVersion)
    {
        if (key is null)
        {
            return ManagementKeyState.Unknown;
        }

        if (key.IsDefault)
        {
            return ManagementKeyState.Default;
        }

        return recordedVersion > 0 ? ManagementKeyState.Diversified : ManagementKeyState.Lost;
    }
}
