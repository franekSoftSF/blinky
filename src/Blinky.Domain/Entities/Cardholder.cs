namespace Blinky.Domain.Entities;

/// <summary>The person a credential belongs to.</summary>
public class Cardholder
{
    public virtual Guid Id { get; protected set; }

    public virtual string DisplayName { get; set; } = string.Empty;

    /// <summary>user@realm.</summary>
    public virtual string? Upn { get; set; }

    /// <summary>
    /// The directory SID, resolved at onboarding rather than at issuance.
    /// Without it a smart-card logon certificate will not authenticate anybody
    /// since the KB5014754 enforcement change - see
    /// docs/04-pki-backends.md#strong-certificate-mapping. Resolving it early
    /// means the failure surfaces during onboarding instead of three weeks
    /// later.
    /// </summary>
    public virtual string? ObjectSid { get; set; }

    public virtual string? DistinguishedName { get; set; }

    public virtual DirectorySource DirectorySource { get; set; } = DirectorySource.Local;

    public virtual CardholderState State { get; set; } = CardholderState.Active;

    public virtual DateTime CreatedAt { get; set; }

    public virtual DateTime UpdatedAt { get; set; }
}
