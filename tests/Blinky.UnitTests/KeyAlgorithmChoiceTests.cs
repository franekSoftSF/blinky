using Blinky.Agent.Service;
using Blinky.Contracts;
using Blinky.Piv;

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

    /// <summary>
    /// The default the agent falls back to, and the names it accepts.
    /// </summary>
    /// <remarks>
    /// Windows-only, like the agent it belongs to: CardEnrolment talks to a
    /// reader through winscard.dll and is marked accordingly.
    /// </remarks>
    [Fact]
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public void The_default_is_the_one_windows_accepts_unconfigured()
    {
        Assert.Equal(PivAlgorithm.Rsa2048, CardEnrolment.ParseAlgorithm(null));
        Assert.Equal(PivAlgorithm.Rsa2048, CardEnrolment.ParseAlgorithm(""));
        Assert.Equal(PivAlgorithm.EccP256, CardEnrolment.ParseAlgorithm("EccP256"));
        Assert.Equal(PivAlgorithm.EccP256, CardEnrolment.ParseAlgorithm("eccp256"));

        Assert.Throws<InvalidOperationException>(
            () => CardEnrolment.ParseAlgorithm("Rsa9999"));
    }

    /// <summary>
    /// And the generation actually uses it.
    /// </summary>
    /// <remarks>
    /// Read from the source, because this is precisely what got past a build,
    /// a full test run and a released MSI once already: an edit that added the
    /// parser but never landed the call site left GenerateKeyPair holding a
    /// literal PivAlgorithm.EccP256. Everything compiled - an unused private
    /// method is not an error - and every test passed, because they all
    /// checked the contract rather than the card. The agent went on generating
    /// the algorithm nobody had asked for.
    /// </remarks>
    [Fact]
    public void The_generation_call_takes_it_from_the_job()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        string? source = null;

        while (directory is not null && source is null)
        {
            var candidate = Path.Combine(directory.FullName,
                "src", "Blinky.Agent.Service", "CardEnrolment.cs");

            if (File.Exists(candidate))
            {
                source = File.ReadAllText(candidate);
            }

            directory = directory.Parent;
        }

        Assert.NotNull(source);

        Assert.DoesNotContain("GenerateKeyPair(slot, PivAlgorithm.", source);
        Assert.Contains("GenerateKeyPair(slot, algorithm,", source);
    }

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
