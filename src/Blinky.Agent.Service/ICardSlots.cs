using Blinky.Contracts;

namespace Blinky.Agent.Service;

/// <summary>
/// Everything anything asks a card to do, without naming where it runs.
/// </summary>
/// <remarks>
/// The same reason <see cref="ICardEnrolment"/> exists. The implementation ends
/// at <c>winscard.dll</c> and is Windows-only; the job executor and the request
/// server have no business saying so, and patch 0017's Linux agent implements
/// this instead of being special-cased in both.
/// </remarks>
public interface ICardSlots
{
    Task<IReadOnlyList<TokenView>> ListTokensAsync(CancellationToken ct);

    AgentResponse ReadCertificate(long serial, string? slotId);

    /// <param name="ordered">
    /// True when the backend asked. It is the only way a credential Blinky
    /// issued comes off a token: the refusal exists to stop a person doing it
    /// from a tray, not to stop the server withdrawing its own credential.
    /// </param>
    Task<AgentResponse> DeleteCertificateAsync(long serial, string? slotId, bool alsoTheKey,
        CancellationToken ct, bool ordered = false);

    AgentResponse ChangePin(long serial, string? currentPin, string? newPin,
        PinComplexityPolicy policy);
}
