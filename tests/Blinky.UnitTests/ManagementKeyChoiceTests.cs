using Blinky.Agent.Service;

namespace Blinky.UnitTests;

/// <summary>
/// Which management key the agent reaches for, and when it personalises.
/// </summary>
/// <remarks>
/// The card will not say which key it holds - only whether the key is still
/// the factory one. Everything else is inference, and the cost of getting it
/// wrong is a failed authentication per attempt, or worse: replacing a key
/// somebody else set on a card this deployment does not own.
/// </remarks>
public class ManagementKeyChoiceTests
{
    [Fact]
    public void A_factory_card_is_opened_with_the_factory_key()
    {
        var plan = ManagementKeyChoice.For(cardSaysFactory: true, haveDerived: true);

        Assert.Equal([ManagementKeySource.Factory], plan.Order);
    }

    /// <summary>
    /// And personalised, because that is the one moment it can be.
    /// </summary>
    [Fact]
    public void A_factory_card_is_personalised()
    {
        Assert.True(ManagementKeyChoice.For(cardSaysFactory: true, haveDerived: true)
            .ShouldPersonalise);
    }

    /// <summary>
    /// A card that is not on the factory key is never personalised.
    /// </summary>
    /// <remarks>
    /// Its key belongs to whoever set it - this deployment under a previous
    /// master, another deployment, or the YubiKey minidriver. Replacing it
    /// because we happened to open the card would take the card away from
    /// them, and there is no way to tell those three apart from here.
    /// </remarks>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void A_personalised_card_is_left_as_it_is(bool haveDerived)
    {
        Assert.False(ManagementKeyChoice.For(cardSaysFactory: false, haveDerived)
            .ShouldPersonalise);
    }

    /// <summary>
    /// Ours before the one behind the PIN.
    /// </summary>
    /// <remarks>
    /// Order matters for a reason that is not performance: reading the key
    /// behind the PIN means asking a person for their PIN before anything has
    /// happened. Trying our own first costs one APDU and no interruption.
    /// </remarks>
    [Fact]
    public void Our_own_key_is_tried_before_the_one_behind_the_pin()
    {
        var plan = ManagementKeyChoice.For(cardSaysFactory: false, haveDerived: true);

        Assert.Equal(
            [ManagementKeySource.Derived, ManagementKeySource.BehindPin],
            plan.Order);
    }

    /// <summary>
    /// Without a master there is nothing to derive, so only one thing is left.
    /// </summary>
    [Fact]
    public void Without_a_master_only_the_pin_protected_key_remains()
    {
        var plan = ManagementKeyChoice.For(cardSaysFactory: false, haveDerived: false);

        Assert.Equal([ManagementKeySource.BehindPin], plan.Order);
        Assert.False(plan.ShouldPersonalise);
    }

    /// <summary>
    /// And a factory card with no master is opened and left alone.
    /// </summary>
    [Fact]
    public void A_factory_card_without_a_master_is_not_personalised()
    {
        var plan = ManagementKeyChoice.For(cardSaysFactory: true, haveDerived: false);

        Assert.Equal([ManagementKeySource.Factory], plan.Order);
        Assert.False(plan.ShouldPersonalise);
    }

    /// <summary>There is always something to try.</summary>
    [Theory]
    [InlineData(true, true)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(false, false)]
    public void The_order_is_never_empty(bool factory, bool derived)
    {
        Assert.NotEmpty(ManagementKeyChoice.For(factory, derived).Order);
    }
}
