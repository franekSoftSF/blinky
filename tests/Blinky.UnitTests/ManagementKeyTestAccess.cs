using Blinky.Piv;

namespace Blinky.UnitTests;

/// <summary>
/// Reaches the two internals a test needs and production code uses.
/// </summary>
/// <remarks>
/// PrintedObjectValue and Encrypt are internal because a management key's bytes
/// should leave the class in as few places as possible. That is right, and it
/// also means the round trip between writing the PRINTED object and parsing it
/// cannot be tested from outside - so this sits here rather than widening the
/// surface of the key itself.
/// </remarks>
internal static class ManagementKeyTestAccess
{
    public static byte[] PrintedObjectValue(ManagementKey key) => key.PrintedObjectValue();

    public static byte[] Encrypt(ManagementKey key, byte[] block) => key.Encrypt(block);

    public static byte[] SetCommandData(ManagementKey key) => key.SetCommandData();
}
