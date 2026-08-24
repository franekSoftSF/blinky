using Blinky.Piv;

namespace Blinky.Agent.Service;

/// <summary>
/// Which management key to try on a card, and in which order.
/// </summary>
/// <remarks>
/// There are three keys a card in this system may be holding, and which one it
/// is cannot be asked directly - the card says only whether the key is still
/// the factory value.
///
///   The factory key. A card nobody has personalised, including every card
///   Blinky has issued to so far.
///
///   The key this deployment derives for it. A card Blinky has personalised.
///
///   Something else entirely, kept behind the card's PIN. That is what the
///   YubiKey minidriver leaves behind when it takes ownership - and since that
///   driver is what makes smart-card logon work on Windows, a card that can log
///   on is quite likely to be in this state.
///
/// Getting the order wrong is not free. Every failed authentication is an
/// APDU that the card answers with 6982, and a card walked through all three
/// on every operation is slow and noisy in the log. So the order follows what
/// the card has already said about itself.
/// </remarks>
public enum ManagementKeySource
{
    /// <summary>The value every PIV card leaves the factory with.</summary>
    Factory,

    /// <summary>Derived for this token from this deployment's master.</summary>
    Derived,

    /// <summary>Read out of the card's PRINTED object, after the PIN.</summary>
    BehindPin,
}

/// <summary>What to try, in order, and whether to personalise afterwards.</summary>
/// <param name="Order">
/// The sources to attempt, most likely first. Never empty.
/// </param>
/// <param name="ShouldPersonalise">
/// Whether this card should be given its derived key once it is open. True
/// only for a card still on the factory value, in a deployment that has a
/// master: personalising anything else would replace a key somebody else set,
/// on a card this deployment does not own.
/// </param>
public readonly record struct ManagementKeyPlan(
    IReadOnlyList<ManagementKeySource> Order,
    bool ShouldPersonalise);

/// <summary>Decides <see cref="ManagementKeyPlan"/> from what the card reports.</summary>
public static class ManagementKeyChoice
{
    /// <param name="cardSaysFactory">
    /// The card's own answer, from its metadata. Firmware that will not say is
    /// treated as "not the factory key", because assuming the factory value and
    /// being wrong costs a failed authentication, while assuming the opposite
    /// costs nothing but order.
    /// </param>
    /// <param name="haveDerived">
    /// Whether this deployment configured a master. Without one there is no
    /// derived key to try and none to personalise with.
    /// </param>
    public static ManagementKeyPlan For(bool cardSaysFactory, bool haveDerived)
    {
        if (cardSaysFactory)
        {
            // Nothing else can be true at the same time, so this is the whole
            // order. Personalise if there is anything to personalise with.
            return new ManagementKeyPlan([ManagementKeySource.Factory], haveDerived);
        }

        // Not the factory key, so it is ours or somebody else's. Ours first: it
        // costs one APDU and needs no PIN, while reading the other one means
        // asking a person for their PIN before anything has been done.
        var order = haveDerived
            ? new[] { ManagementKeySource.Derived, ManagementKeySource.BehindPin }
            : [ManagementKeySource.BehindPin];

        return new ManagementKeyPlan(order, ShouldPersonalise: false);
    }
}
