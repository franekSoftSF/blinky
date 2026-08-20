namespace Blinky.Piv;

/// <summary>
/// Turns a status word into a typed exception. Every entry in the error map in
/// docs/03-piv-layer.md is represented; anything else becomes
/// <see cref="PivUnexpectedStatusException"/> rather than being swallowed.
/// </summary>
public static class PivStatus
{
    /// <summary>Creates the exception for a status word without throwing it.</summary>
    public static PivException ToException(StatusWord status, string operation) => status.Value switch
    {
        StatusWord.SecurityStatusNotSatisfied =>
            new PivSecurityStatusNotSatisfiedException(status, operation),
        StatusWord.AuthenticationMethodBlocked =>
            new PivAuthenticationBlockedException(status, operation),
        StatusWord.IncorrectParameters =>
            new PivIncorrectParametersException(status, operation),
        StatusWord.FileNotFound =>
            new PivDataObjectNotFoundException(status, operation),
        StatusWord.ReferencedDataNotFound =>
            new PivReferencedDataNotFoundException(status, operation),
        StatusWord.WrongLength =>
            new PivWrongLengthException(status, operation),
        StatusWord.InstructionNotSupported =>
            new PivInstructionNotSupportedException(status, operation),
        _ when status.RetriesLeft is { } retries =>
            new PivVerificationFailedException(status, operation, retries),
        _ => new PivUnexpectedStatusException(status, operation),
    };

    /// <summary>Throws unless the card said 9000.</summary>
    public static void ThrowIfFailed(StatusWord status, string operation)
    {
        if (!status.IsSuccess)
        {
            throw ToException(status, operation);
        }
    }
}
