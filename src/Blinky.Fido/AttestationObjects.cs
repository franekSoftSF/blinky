using System.Formats.Cbor;

namespace Blinky.Fido;

/// <summary>WebAuthn's attestationObject, from the parts CTAP returns.</summary>
public static class AttestationObjects
{
    /// <summary>
    /// <c>{"fmt": …, "authData": …, "attStmt": …}</c>, the map a browser hands a
    /// relying party.
    /// </summary>
    /// <remarks>
    /// CTAP's makeCredential answer keys the same three things by number, so this
    /// one re-encoding is unavoidable and every client makes it. What is not
    /// re-encoded is what the signature covers or the provider parses: authData
    /// goes in as the key's bytes, and the attestation statement is written as the
    /// key's own CBOR, not decoded and written back - a library that sorted its
    /// map on the way through would hand Entra an <c>x5c</c> it never signed.
    /// </remarks>
    public static byte[] Build(string format, ReadOnlySpan<byte> authenticatorData, ReadOnlySpan<byte> attestationStatement)
    {
        var writer = new CborWriter(CborConformanceMode.Lax);
        writer.WriteStartMap(3);
        writer.WriteTextString("fmt");
        writer.WriteTextString(format);
        writer.WriteTextString("attStmt");
        writer.WriteEncodedValue(attestationStatement);
        writer.WriteTextString("authData");
        writer.WriteByteString(authenticatorData);
        writer.WriteEndMap();

        return writer.Encode();
    }
}
