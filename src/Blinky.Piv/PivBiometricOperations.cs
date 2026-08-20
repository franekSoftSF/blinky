namespace Blinky.Piv;

/// <summary>
/// Proving who you are with a finger instead of a PIN.
/// </summary>
/// <remarks>
/// <para>
/// A YubiKey Bio Multi-protocol verifies the user by matching a fingerprint on
/// the card, and PIV addresses that as slot <c>96</c>. It satisfies the same
/// PIN policy a <c>VERIFY</c> would: after a successful match, a key with
/// policy <c>Once</c> will sign for the rest of the session.
/// </para>
/// <para>
/// <b>The encodings here were measured, not read.</b> Doc 03 carried them as
/// unverified for months, with the reason attached: finding out costs a match
/// attempt and needs somebody's finger on the sensor. Confirmed on firmware
/// 5.7.2 on 20 August 2026:
/// </para>
/// <code>
/// VERIFY 96, no data      →  63C3   three attempts, none consumed
/// VERIFY 96, data 03 00   →  9000   the sensor lights, the match runs
/// VERIFY 96, data 02 00   →  9000   plus sixteen bytes: a temporary PIN
/// VERIFY 96, data 00      →  6A80   not an encoding this card knows
/// </code>
/// <para>
/// The last line is why guessing would have been expensive rather than free:
/// the wrong shape is refused without consuming anything, but the right one
/// waits for a finger, and a person who is not expecting that sees a program
/// that has hung.
/// </para>
/// </remarks>
public partial class PivSession
{
    /// <summary>Empty TLV, tag 03: run the match.</summary>
    private static readonly byte[] RequestMatch = [0x03, 0x00];

    /// <summary>Empty TLV, tag 02: run the match and return a temporary PIN.</summary>
    private static readonly byte[] RequestTemporaryPin = [0x02, 0x00];

    /// <summary>
    /// How many match attempts are left, without spending one.
    /// </summary>
    /// <returns>
    /// Null on a token with no on-card comparison — which is how the question
    /// is answered, rather than by the model name on the plastic.
    /// </returns>
    public int? GetBiometricAttempts()
    {
        var response = Connection.Send(new ApduCommand(InsVerify, p2: BiometricSlot));

        // 6A88: no such reference data. Every non-Bio token says this.
        if (response.Status.Value == 0x6A88)
        {
            return null;
        }

        // Already verified in this session, so nothing is outstanding.
        return response.Status.IsSuccess ? 0 : response.Status.RetriesLeft;
    }

    /// <summary>
    /// Asks the card to match a fingerprint. Blocks until the person touches
    /// the sensor or the card gives up.
    /// </summary>
    /// <remarks>
    /// The caller must have told somebody to present a finger before calling
    /// this. The sensor lights on its own, but a lit sensor beside a window
    /// that says nothing is a program that appears to have frozen.
    /// </remarks>
    /// <exception cref="PivVerificationFailedException">
    /// The match failed, with the attempts the card says are left. At zero the
    /// biometrics are blocked and the PIN is the way in — on a Bio that is the
    /// only way in, because the product line ships with no PUK.
    /// </exception>
    public void VerifyBiometric()
    {
        var response = Connection.Send(
            new ApduCommand(InsVerify, p2: BiometricSlot, data: RequestMatch));

        if (response.Status.RetriesLeft is { } remaining)
        {
            throw new PivVerificationFailedException(response.Status, "VERIFY (biometric)",
                remaining);
        }

        PivStatus.ThrowIfFailed(response.Status, "VERIFY (biometric)");
    }

    /// <summary>
    /// Matches a fingerprint and asks for a temporary PIN in the same breath.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Sixteen bytes that stand in for the PIN until the card is released. What
    /// it buys is a profile with PIN policy <c>Always</c> staying usable on a
    /// Bio without asking for a finger before every single operation.
    /// </para>
    /// <para>
    /// It is a live credential for the length of a session. Never logged, never
    /// written down, and it does not leave the process that asked for it.
    /// </para>
    /// </remarks>
    public byte[] VerifyBiometricForTemporaryPin()
    {
        var response = Connection.Send(
            new ApduCommand(InsVerify, p2: BiometricSlot, data: RequestTemporaryPin, le: 0));

        if (response.Status.RetriesLeft is { } remaining)
        {
            throw new PivVerificationFailedException(response.Status,
                "VERIFY (biometric, temporary PIN)", remaining);
        }

        PivStatus.ThrowIfFailed(response.Status, "VERIFY (biometric, temporary PIN)");

        return response.Data.Length > 0
            ? response.Data.ToArray()
            : throw new PivProtocolException("The card matched but returned no temporary PIN.");
    }
}
