namespace Blinky.Piv;

/// <summary>One response APDU: the data the card returned, and its verdict.</summary>
public sealed record ApduResponse(byte[] Data, StatusWord Status)
{
    public bool IsSuccess => Status.IsSuccess;

    /// <summary>Splits a raw transmission into payload and status word.</summary>
    public static ApduResponse Parse(ReadOnlySpan<byte> raw)
    {
        var status = StatusWord.FromResponse(raw);
        return new ApduResponse(raw[..^2].ToArray(), status);
    }

    public override string ToString() => $"{Data.Length} bytes, SW={Status}";
}
