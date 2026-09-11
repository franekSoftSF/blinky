using Blinky.Secrets;

namespace Blinky.UnitTests;

/// <summary>
/// Every use of a master secret is recorded, and nothing about the secret is.
/// </summary>
/// <remarks>
/// The sibling of <see cref="ApduRedactionTests"/>, and written for the same
/// reason: the PIN reached a database column once, through a failure message
/// that nobody had thought of as a place secrets go. An audit record is exactly
/// that sort of place - it is written on the unhappy path, it is kept longer
/// than anything else, and it is the last thing anybody reads before deciding
/// what happened.
/// </remarks>
public class KeyUseAuditTests
{
    private static readonly KeyRef Key = new(KeyPurpose.ManagementKeyMaster, 1);

    private static ConfigurationKeyProvider Inner(byte fill = 0x5A)
    {
        var secret = new byte[32];
        Array.Fill(secret, fill);

        return new ConfigurationKeyProvider(new Dictionary<KeyRef, byte[]> { [Key] = secret });
    }

    [Fact]
    public void Every_use_is_counted()
    {
        var seen = new List<KeyUse>();
        using var provider = new AuditingKeyProvider(Inner(), seen.Add);

        provider.Mac(Key, "one"u8);
        provider.Mac(Key, "two"u8);

        Assert.Equal(2, seen.Count);
        Assert.Equal(2, provider.Usage[Key].Operations);
        Assert.Equal(0, provider.Usage[Key].Failures);
    }

    /// <summary>
    /// A refusal is counted as one, and the count is what a status page can
    /// alert on. A device that has started saying no is not visible any other
    /// way until an enrolment fails.
    /// </summary>
    [Fact]
    public void A_refusal_is_counted_and_still_thrown()
    {
        var seen = new List<KeyUse>();
        using var provider = new AuditingKeyProvider(Inner(), seen.Add);

        var absent = new KeyRef(KeyPurpose.PukKek, 2);

        Assert.Throws<KeyUnavailableException>(() => provider.Mac(absent, "anything"u8));

        Assert.Equal(1, provider.Usage[absent].Failures);
        Assert.Equal(1, provider.Usage[absent].Operations);
        Assert.NotNull(seen.Single().Failure);
    }

    /// <summary>
    /// <b>The guard.</b> Neither the input nor the output appears in what is
    /// recorded, in any encoding a log would render.
    /// </summary>
    /// <remarks>
    /// Checked against the record's own <c>ToString</c> rather than against a
    /// hand-written format string, because a record prints every field it has -
    /// so this fails the moment somebody adds one holding the data, which is
    /// the mistake worth catching.
    /// </remarks>
    [Fact]
    public void Neither_the_input_nor_the_output_is_recorded()
    {
        var seen = new List<KeyUse>();
        using var provider = new AuditingKeyProvider(Inner(), seen.Add);

        var input = "a-serial-and-a-domain-string"u8.ToArray();
        var output = provider.Mac(Key, input);

        var written = seen.Single().ToString();

        foreach (var forbidden in new[]
                 {
                     Convert.ToHexString(input),
                     Convert.ToBase64String(input),
                     System.Text.Encoding.UTF8.GetString(input),
                     Convert.ToHexString(output),
                     Convert.ToBase64String(output),
                 })
        {
            Assert.DoesNotContain(forbidden, written, StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// What is recorded instead: which key, how much went in, and how long it
    /// took. Enough to see that a device is being used and that it is answering.
    /// </summary>
    [Fact]
    public void What_is_recorded_is_enough_to_be_useful()
    {
        var seen = new List<KeyUse>();
        using var provider = new AuditingKeyProvider(Inner(), seen.Add);

        provider.Mac(Key, "twelve bytes"u8);

        var use = seen.Single();

        Assert.Equal(Key, use.Key);
        Assert.Equal("configuration", use.Provider);
        Assert.Equal("hmac-sha256", use.Operation);
        Assert.Equal(12, use.InputBytes);
        Assert.Null(use.Failure);
    }

    /// <summary>
    /// The decorator changes nothing about the answer.
    /// </summary>
    [Fact]
    public void The_result_is_the_providers_own()
    {
        using var bare = Inner();
        using var audited = new AuditingKeyProvider(Inner(), _ => { });

        Assert.Equal(bare.Mac(Key, "same"u8), audited.Mac(Key, "same"u8));
    }
}
