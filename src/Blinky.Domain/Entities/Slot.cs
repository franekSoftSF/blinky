namespace Blinky.Domain.Entities;

/// <summary>One PIV slot on one token.</summary>
public class Slot
{
    public virtual Guid Id { get; protected set; }

    public virtual Token Token { get; set; } = null!;

    /// <summary>"9A", "9C", "9D", "9E", or a retired slot "82".."95".</summary>
    public virtual string SlotId { get; set; } = string.Empty;

    public virtual SlotState State { get; set; } = SlotState.Empty;

    public virtual Credential? Credential { get; set; }

    public virtual string? KeyAlgorithm { get; set; }

    public virtual string? PinPolicy { get; set; }

    public virtual string? TouchPolicy { get; set; }

    /// <summary>
    /// SHA-256 of the public key the card reports, so a certificate swapped in
    /// from outside Blinky is detected rather than silently accepted.
    /// </summary>
    public virtual byte[]? PublicKeySha256 { get; set; }

    public virtual DateTime UpdatedAt { get; set; }
}
