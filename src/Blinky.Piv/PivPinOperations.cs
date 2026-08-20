namespace Blinky.Piv;

/// <summary>
/// Changing what a person types: the PIN, the PUK, and getting back in.
/// </summary>
/// <remarks>
/// <para>
/// Separate from the rest of the write path because these are the operations
/// that can lock somebody out of their own token. A wrong PIN costs an attempt.
/// A wrong PUK costs a PUK attempt, and when those run out the card is not
/// recoverable by any means Blinky has — the key material stays on it,
/// unreachable, until somebody resets the applet and destroys it.
/// </para>
/// <para>
/// Nothing here logs, returns or stores a value. The parameters are the only
/// place a PIN exists.
/// </para>
/// </remarks>
public partial class PivSession
{
    private const byte InsChangeReferenceData = 0x24;
    private const byte InsResetRetryCounter = 0x2C;

    /// <summary>Changes the PIN, given the current one.</summary>
    /// <exception cref="PivVerificationFailedException">
    /// The current PIN was wrong. The exception carries what the card said is
    /// left, which is the only number worth showing a person at this point.
    /// </exception>
    public void ChangePin(ReadOnlySpan<char> currentPin, ReadOnlySpan<char> newPin) =>
        ChangeReference(PinSlot, currentPin, newPin, "CHANGE PIN");

    /// <summary>Changes the PUK, given the current one.</summary>
    public void ChangePuk(ReadOnlySpan<char> currentPuk, ReadOnlySpan<char> newPuk) =>
        ChangeReference(PukSlot, currentPuk, newPuk, "CHANGE PUK");

    /// <summary>
    /// Sets a new PIN using the PUK, which is the only way back from a blocked
    /// one.
    /// </summary>
    /// <remarks>
    /// The card does not care whether the PIN was blocked: this works on a
    /// healthy token too, and resets the attempt counter either way.
    /// </remarks>
    public void UnblockPin(ReadOnlySpan<char> puk, ReadOnlySpan<char> newPin)
    {
        Span<byte> data = stackalloc byte[16];
        Pad(puk, data[..8], "PUK");
        Pad(newPin, data[8..], "PIN");

        Send(InsResetRetryCounter, PinSlot, data, "RESET RETRY COUNTER");
    }

    private void ChangeReference(byte slot, ReadOnlySpan<char> current, ReadOnlySpan<char> replacement,
        string operation)
    {
        Span<byte> data = stackalloc byte[16];
        Pad(current, data[..8], "value");
        Pad(replacement, data[8..], "value");

        Send(InsChangeReferenceData, slot, data, operation);
    }

    private void Send(byte instruction, byte slot, ReadOnlySpan<byte> data, string operation)
    {
        var response = Connection.Send(new ApduCommand(instruction, p2: slot,
            data: data.ToArray()));

        // A retry count in the status word means the card rejected what it was
        // given rather than failing at it, and the count is the difference
        // between "try again" and "you have one left".
        if (response.Status.RetriesLeft is { } remaining)
        {
            throw new PivVerificationFailedException(response.Status, operation, remaining);
        }

        PivStatus.ThrowIfFailed(response.Status, operation);
    }

    /// <summary>
    /// Writes six to eight characters into an eight-byte field padded with
    /// <c>FF</c>, which is how PIV carries both a PIN and a PUK.
    /// </summary>
    /// <remarks>
    /// The length is checked before anything is written. Encoding first and
    /// asking afterwards throws an unhelpful buffer exception on a nine
    /// character value, which is a thing people type.
    /// </remarks>
    private static void Pad(ReadOnlySpan<char> value, Span<byte> destination, string what)
    {
        if (value.Length is < 6 or > 8)
        {
            throw new ArgumentException($"A PIV {what} is between six and eight characters.",
                nameof(value));
        }

        destination.Fill(0xFF);
        System.Text.Encoding.ASCII.GetBytes(value, destination);
    }
}
