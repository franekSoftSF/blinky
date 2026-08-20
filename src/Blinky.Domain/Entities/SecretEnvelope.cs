namespace Blinky.Domain.Entities;

/// <summary>
/// Encrypted material at rest. Never a PIN: PINs are not stored in any form,
/// and a workflow that appears to need one is wrong.
/// </summary>
public class SecretEnvelope
{
    public virtual Guid Id { get; protected set; }

    public virtual Token Token { get; set; } = null!;

    public virtual SecretKind Kind { get; set; }

    /// <summary>Which KEK generation encrypted this.</summary>
    public virtual int KeyVersion { get; set; }

    public virtual byte[] Ciphertext { get; set; } = [];

    public virtual byte[] Nonce { get; set; } = [];

    public virtual byte[] Tag { get; set; } = [];

    /// <summary>
    /// Additional authenticated data, "puk|serial", so a ciphertext cannot be
    /// moved from one token's row to another's.
    /// </summary>
    public virtual string AssociatedData { get; set; } = string.Empty;

    public virtual DateTime CreatedAt { get; set; }
}
