namespace Blinky.Secrets;

/// <summary>
/// What a long-lived secret is <i>for</i>. One purpose, one key, always.
/// </summary>
/// <remarks>
/// Separated rather than shared because a single master used for two things is
/// a single master whose rotation is blocked by whichever use is hardest to
/// migrate. docs/06-security.md lists these as distinct secrets with distinct
/// consequences; this enum is that list, in code.
/// </remarks>
public enum KeyPurpose
{
    /// <summary>
    /// The root of every token's management key. Compromise means every managed
    /// token can be reprogrammed.
    /// </summary>
    ManagementKeyMaster,

    /// <summary>
    /// The root of every escrowed PUK envelope. Compromise means every PUK.
    /// </summary>
    PukKek,
}

/// <summary>
/// One key, named by what it is for and which generation it belongs to.
/// </summary>
/// <remarks>
/// <para>
/// The version is here rather than in configuration per key because rotation is
/// the reason this type exists. A new generation is a new object in the device
/// beside the old one, not a replacement: envelopes written under version one
/// have to stay readable while version two is what gets written, and a rotation
/// that cannot overlap is a rotation nobody performs.
/// </para>
/// <para>
/// The label is derived rather than configured. Two deployments naming the same
/// key differently is a support call, and there is nothing to gain from letting
/// them.
/// </para>
/// </remarks>
public readonly record struct KeyRef(KeyPurpose Purpose, int Version)
{
    /// <summary>The object label inside the device.</summary>
    public string Label => $"blinky/{Slug}/v{Version}";

    /// <summary>
    /// The same string, as the derivation's domain separator.
    /// </summary>
    /// <remarks>
    /// Deliberately the same value as <see cref="Label"/>: a derivation bound
    /// to a label cannot silently start using a different key than the one its
    /// output claims to come from.
    /// </remarks>
    public string Domain => Label;

    private string Slug => Purpose switch
    {
        KeyPurpose.ManagementKeyMaster => "management-key",
        KeyPurpose.PukKek => "puk-kek",
        _ => throw new ArgumentOutOfRangeException(nameof(Purpose), Purpose, "No slug for this purpose."),
    };

    public override string ToString() => Label;
}
