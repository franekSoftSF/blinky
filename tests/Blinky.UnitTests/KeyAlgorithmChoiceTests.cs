using Blinky.Contracts;

namespace Blinky.UnitTests;

/// <summary>
/// The key algorithm travels from the console to the card.
/// </summary>
/// <remarks>
/// It used to be written into the agent, so a deployment had no say. That
/// matters more than a hard-coded constant usually does, because the two
/// choices are not interchangeable in front of Windows: the inbox smart-card
/// credential provider does not enumerate ECC certificates unless
/// EnumerateECCCerts is set on the workstation. A perfectly good ECC
/// credential then produces "no valid certificates were found on this smart
/// card" at the logon screen - a sentence about the card, for a policy
/// setting - and certutil reports a missing keyset for a key the card will
/// describe on request.
/// </remarks>
public class KeyAlgorithmChoiceTests
{
    private static JobStep StepOf(string? algorithm) =>
        JobEnvelope.Enrolment(Guid.NewGuid(), "key", DateTimeOffset.UtcNow.AddHours(1),
                123, "9A", "smartcard-logon", "Jan Kowalski",
                "jkowalski@blinky.lab", "S-1-5-21-1-2-3-1104", algorithm)
            .Steps[0];

    [Fact]
    public void The_choice_reaches_the_agent()
    {
        Assert.Equal("Rsa2048", StepOf("Rsa2048").Argument("keyAlgorithm"));
        Assert.Equal("EccP256", StepOf("EccP256").Argument("keyAlgorithm"));
    }

    /// <summary>
    /// And no choice is carried as no choice, rather than as a value.
    /// </summary>
    /// <remarks>
    /// An agent too old to read this argument ignores it either way. Sending a
    /// name it does not understand would be a request that appears to have been
    /// honoured and was not - the job succeeds, the card holds a key of the
    /// other kind, and nothing anywhere says so.
    /// </remarks>
    [Fact]
    public void No_choice_is_carried_as_no_choice()
    {
        Assert.Equal(string.Empty, StepOf(null).Argument("keyAlgorithm"));
    }

    /// <summary>
    /// Two algorithms on one slot are two requests.
    /// </summary>
    /// <remarks>
    /// The idempotency key decides whether a post creates work or returns the
    /// job that already ran. Without the algorithm in it, asking for RSA on a
    /// card that just received ECC returns the finished ECC job and changes
    /// nothing - which is exactly what somebody does after discovering the
    /// first one will not log on.
    /// </remarks>
    [Fact]
    public void A_different_algorithm_is_a_different_request()
    {
        static string Key(string? algorithm) =>
            $"enrol:123:9A:smartcard-logon:{algorithm ?? "default"}:initial";

        Assert.NotEqual(Key("Rsa2048"), Key("EccP256"));
        Assert.NotEqual(Key(null), Key("Rsa2048"));
    }
}
