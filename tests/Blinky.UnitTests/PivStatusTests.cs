using Blinky.Piv;

namespace Blinky.UnitTests;

public sealed class PivStatusTests
{
    /// <summary>
    /// Every status word in the error map of docs/03-piv-layer.md, and the type
    /// the caller has to catch. The table is the contract: a caller deciding
    /// whether to retry, prompt, or give up branches on these types.
    /// </summary>
    public static TheoryData<ushort, Type> ErrorMap => new()
    {
        { 0x6982, typeof(PivSecurityStatusNotSatisfiedException) },
        { 0x6983, typeof(PivAuthenticationBlockedException) },
        { 0x6A80, typeof(PivIncorrectParametersException) },
        { 0x6A82, typeof(PivDataObjectNotFoundException) },
        { 0x6A88, typeof(PivReferencedDataNotFoundException) },
        { 0x6700, typeof(PivWrongLengthException) },
        { 0x6D00, typeof(PivInstructionNotSupportedException) },
        { 0x63C3, typeof(PivVerificationFailedException) },
        { 0x63C0, typeof(PivVerificationFailedException) },
        { 0x6F00, typeof(PivUnexpectedStatusException) },
    };

    [Theory]
    [MemberData(nameof(ErrorMap))]
    public void Each_status_word_maps_to_its_type(ushort status, Type expected)
    {
        var exception = PivStatus.ToException(new StatusWord(status), "TEST");

        Assert.IsType(expected, exception);
        Assert.Equal(status, exception.Status.Value);
    }

    [Fact]
    public void Success_does_not_throw()
    {
        PivStatus.ThrowIfFailed(new StatusWord(StatusWord.Success), "TEST");
    }

    [Fact]
    public void The_message_always_carries_the_status_word_and_the_operation()
    {
        // These failures are read off someone else's screen. A message without
        // the status word is not a diagnosis.
        var exception = PivStatus.ToException(new StatusWord(0x6982), "GENERATE KEY 9A");

        Assert.Contains("6982", exception.Message, StringComparison.Ordinal);
        Assert.Contains("GENERATE KEY 9A", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Retry_count_survives_into_the_exception()
    {
        var exception = Assert.IsType<PivVerificationFailedException>(
            PivStatus.ToException(new StatusWord(0x63C2), "VERIFY"));

        Assert.Equal(2, exception.RetriesLeft);
    }

    [Fact]
    public void Blocked_is_a_different_type_from_no_retries_left()
    {
        // 6983 and 63C0 both mean "not getting in", but only one of them is
        // fixed by knowing the PIN. One routes to the unblock workflow, the
        // other to another prompt.
        Assert.IsType<PivAuthenticationBlockedException>(
            PivStatus.ToException(new StatusWord(0x6983), "VERIFY"));
        Assert.IsType<PivVerificationFailedException>(
            PivStatus.ToException(new StatusWord(0x63C0), "VERIFY"));
    }
}
