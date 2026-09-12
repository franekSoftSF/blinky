using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Blinky.AdcsConnector;

/// <summary>
/// What a <c>PKIData</c> asks for, established before the enrolment agent signs
/// it - and a refusal when it asks for more than one enrolment.
/// </summary>
/// <remarks>
/// <para>
/// The connector signs as the enrolment agent, so whoever holds an allowed client
/// certificate can ask for that signature. This is what stops the question being
/// "sign these bytes": the content has to be a CMC full PKI request carrying
/// exactly one certification request, and nothing else a CMC can carry.
/// </para>
/// <para>
/// Nothing else, strictly, and each refusal is one of the things CMC is able to
/// do. A control can be <c>id-cmc-revokeRequest</c>, which is a signed revocation;
/// a nested <c>cmsSequence</c> can wrap a second, separately signed request; a
/// second <c>TaggedRequest</c> is a second certificate. Blinky's own
/// <c>CmcRequest</c> emits none of those, so refusing all of them costs nothing
/// and closes every one.
/// </para>
/// </remarks>
public sealed record PkiDataInspection(
    uint BodyPartId,
    string Subject,
    string PublicKeySha256)
{
    /// <summary>
    /// Parses <paramref name="pkiData"/> and returns what it asks for, or throws
    /// with the reason it will not be signed.
    /// </summary>
    public static PkiDataInspection Inspect(ReadOnlyMemory<byte> pkiData)
    {
        try
        {
            return Read(pkiData);
        }
        catch (AsnContentException ex)
        {
            throw new PkiDataRefusedException(
                "The content is not a well-formed PKIData: " + ex.Message);
        }
    }

    private static PkiDataInspection Read(ReadOnlyMemory<byte> pkiData)
    {
        var reader = new AsnReader(pkiData, AsnEncodingRules.DER);
        var body = reader.ReadSequence();

        if (reader.HasData)
        {
            throw new PkiDataRefusedException("There are bytes after the PKIData.");
        }

        if (body.ReadSequence().HasData)
        {
            throw new PkiDataRefusedException(
                "The PKIData carries controls. A control can be a revocation request, and "
                + "this connector signs enrolments and nothing else.");
        }

        var requests = body.ReadSequence();

        if (!requests.HasData)
        {
            throw new PkiDataRefusedException("The PKIData carries no certification request.");
        }

        var tag = requests.PeekTag();

        if (tag != new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true))
        {
            // [1] is a CRMF CertReqMsg and [2] is OtherReqMsg. Neither is what a
            // card produces, and accepting a format this code does not read is
            // signing something unread.
            throw new PkiDataRefusedException(
                "The request is not a PKCS#10 tagged certification request.");
        }

        var tagged = requests.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));

        if (requests.HasData)
        {
            throw new PkiDataRefusedException(
                "The PKIData carries more than one certification request. One signature from "
                + "the enrolment agent is one enrolment.");
        }

        if (!tagged.TryReadUInt32(out var bodyPartId))
        {
            throw new PkiDataRefusedException("The body part identifier is out of range.");
        }

        var pkcs10 = tagged.ReadEncodedValue();

        if (tagged.HasData)
        {
            throw new PkiDataRefusedException(
                "There are bytes after the certification request inside its tag.");
        }

        if (body.ReadSequence().HasData)
        {
            throw new PkiDataRefusedException(
                "The PKIData wraps other signed content. A nested request would reach the CA "
                + "under this signature without having been read here.");
        }

        if (body.ReadSequence().HasData)
        {
            throw new PkiDataRefusedException("The PKIData carries other messages.");
        }

        if (body.HasData)
        {
            throw new PkiDataRefusedException("There are bytes after the PKIData's four sequences.");
        }

        var request = Load(pkcs10);

        return new PkiDataInspection(
            bodyPartId,
            request.SubjectName.Name,
            Convert.ToHexString(SHA256.HashData(request.PublicKey.ExportSubjectPublicKeyInfo())));
    }

    /// <summary>
    /// The PKCS#10, with its own signature checked.
    /// </summary>
    /// <remarks>
    /// Checked here although the CA checks it too, because the agent's signature
    /// is applied before the CA sees anything. A request whose proof of possession
    /// does not verify is not an enrolment, and the enrolment agent should not be
    /// on record as having vouched for it.
    /// </remarks>
    private static CertificateRequest Load(ReadOnlyMemory<byte> pkcs10)
    {
        try
        {
            var request = CertificateRequest.LoadSigningRequest(
                pkcs10.Span, HashAlgorithmName.SHA256, out var consumed,
                CertificateRequestLoadOptions.Default);

            if (consumed != pkcs10.Length)
            {
                throw new PkiDataRefusedException("The certification request has trailing bytes.");
            }

            return request;
        }
        catch (CryptographicException ex)
        {
            throw new PkiDataRefusedException(
                "The certification request does not verify against its own key: " + ex.Message);
        }
    }
}

/// <summary>A PKIData the enrolment agent will not sign, with the reason.</summary>
public sealed class PkiDataRefusedException(string message) : Exception(message);
