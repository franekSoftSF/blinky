namespace Blinky.Piv;

/// <summary>
/// A card refused a command. Always carries the status word verbatim: these
/// failures happen on someone else's desk, and "enrolment failed" is not a
/// diagnosis. See docs/03-piv-layer.md.
/// </summary>
public class PivException(StatusWord status, string operation, string explanation)
    : Exception($"{operation} failed with SW {status}: {explanation}")
{
    public StatusWord Status { get; } = status;

    public string Operation { get; } = operation;
}

/// <summary>6982 - the PIN or the management key was not authenticated first.</summary>
public sealed class PivSecurityStatusNotSatisfiedException(StatusWord status, string operation)
    : PivException(status, operation,
        "security status not satisfied - a PIN or the management key was required first. "
        + "This is a sequencing bug, not a user error");

/// <summary>6983 - the PIN or PUK is blocked. Not the same as "no retries left".</summary>
public sealed class PivAuthenticationBlockedException(StatusWord status, string operation)
    : PivException(status, operation,
        "authentication method blocked - the credential is blocked and needs unblocking, "
        + "not another attempt");

/// <summary>63Cx - verification failed, with the number of attempts that remain.</summary>
public sealed class PivVerificationFailedException(StatusWord status, string operation, int retriesLeft)
    : PivException(status, operation, $"verification failed, {retriesLeft} attempts remaining")
{
    public int RetriesLeft { get; } = retriesLeft;
}

/// <summary>6A80 - a malformed command. Ours to fix, never the user's.</summary>
public sealed class PivIncorrectParametersException(StatusWord status, string operation)
    : PivException(status, operation,
        "incorrect parameters in the data field - the command was malformed by this client");

/// <summary>6A82 - no such data object. Expected on an empty slot.</summary>
public sealed class PivDataObjectNotFoundException(StatusWord status, string operation)
    : PivException(status, operation, "data object not found - the slot holds no certificate");

/// <summary>6A88 - no such referenced data. Expected on a slot with no key.</summary>
public sealed class PivReferencedDataNotFoundException(StatusWord status, string operation)
    : PivException(status, operation, "referenced data not found - the slot holds no key");

/// <summary>6700 - wrong length.</summary>
public sealed class PivWrongLengthException(StatusWord status, string operation)
    : PivException(status, operation, "wrong length");

/// <summary>6D00 - the card does not know this instruction. Degrade, do not fail.</summary>
public sealed class PivInstructionNotSupportedException(StatusWord status, string operation)
    : PivException(status, operation,
        "instruction not supported - the firmware predates this command");

/// <summary>Any status word without a more specific meaning.</summary>
public sealed class PivUnexpectedStatusException(StatusWord status, string operation)
    : PivException(status, operation, "unexpected status word");
