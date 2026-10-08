namespace Blinky.Domain;

/// <summary>
/// Passkey lifecycle, the fourth state machine. See docs/02-data-model.md.
/// </summary>
/// <remarks>
/// <see cref="Provisioned"/> and <see cref="Registered"/> are two states for the
/// same reason <c>Issued</c> and <c>Installed</c> are on a certificate: between
/// them a credential exists on the key that the provider has not accepted, and a
/// row stuck in <see cref="Provisioned"/> is the only way to see that the user
/// will be holding a key that opens nothing.
/// </remarks>
public enum PasskeyCredentialState
{
    /// <summary>A job exists; no key has answered yet.</summary>
    Requested,

    /// <summary>The agent reported the key prepared: PIN set, policy applied.</summary>
    KeyReady,

    /// <summary>The provider handed out a challenge, and its clock is running.</summary>
    ChallengeIssued,

    /// <summary>The key made the credential; the provider has not yet said yes.</summary>
    Provisioned,

    /// <summary>The provider accepted it. The user can sign in with it.</summary>
    Registered,

    /// <summary>Deleted at the provider, and only then marked here.</summary>
    Revoked,

    Failed,
}

/// <summary>Which move is allowed from where.</summary>
public static class PasskeyCredentialStates
{
    private static readonly Dictionary<PasskeyCredentialState, PasskeyCredentialState[]> Next = new()
    {
        // KeyReady and ChallengeIssued are re-enterable: a job retried after a
        // lease ran out reports the key ready again and is given a fresh
        // challenge. Re-entering is the same row going round again, which is
        // the truth; a second row for one job would not be.
        [PasskeyCredentialState.Requested] =
            [PasskeyCredentialState.KeyReady, PasskeyCredentialState.Failed],
        [PasskeyCredentialState.KeyReady] =
            [PasskeyCredentialState.KeyReady, PasskeyCredentialState.ChallengeIssued, PasskeyCredentialState.Failed],
        [PasskeyCredentialState.ChallengeIssued] =
            [PasskeyCredentialState.KeyReady, PasskeyCredentialState.ChallengeIssued,
             PasskeyCredentialState.Provisioned, PasskeyCredentialState.Failed],
        [PasskeyCredentialState.Provisioned] =
            [PasskeyCredentialState.Registered, PasskeyCredentialState.Failed],
        [PasskeyCredentialState.Registered] = [PasskeyCredentialState.Revoked],
        [PasskeyCredentialState.Revoked] = [],

        // Final. Trying again is a new job and a new row: the failure is part of
        // the history of that key, not something a retry should overwrite.
        [PasskeyCredentialState.Failed] = [],
    };

    public static bool CanMove(PasskeyCredentialState from, PasskeyCredentialState to) =>
        Next[from].Contains(to);

    public static IReadOnlyList<PasskeyCredentialState> From(PasskeyCredentialState state) => Next[state];
}
