using System.Formats.Asn1;
using System.Security.Cryptography.Pkcs;

namespace Blinky.Pki.Adcs;

/// <summary>
/// A CMC full PKI request carrying somebody else's PKCS#10, signed by an
/// enrolment agent.
/// </summary>
/// <remarks>
/// <para>
/// This is the whole of "enrol on behalf of". The cardholder's key signed the
/// PKCS#10 on the card, which is the proof of possession; the enrolment agent
/// signs the envelope around it, which is the CA's evidence of <i>who was
/// allowed to ask</i>. Neither signature substitutes for the other, and a CA
/// presented with only the first will build a certificate for whoever the
/// request claims to be.
/// </para>
/// <para>
/// RFC 5272. The inner content is <c>PKIData</c> under
/// <c>id-cct-PKIData</c>, and the CMC module is <c>IMPLICIT TAGS</c>, so the
/// <c>[0]</c> on the <c>tcr</c> alternative replaces the SEQUENCE tag of
/// <c>TaggedCertificationRequest</c> rather than wrapping it. Getting that
/// wrong produces a structure a CA rejects with a message about the format.
/// </para>
/// <para>
/// Written by hand with <see cref="AsnWriter"/> because .NET has no CMC type
/// and the structure is four sequences deep. The alternative considered was
/// <c>certenroll</c>'s <c>IX509CertificateRequestCmc</c>, which is COM, which
/// is Windows, which is the thing the container cannot do and the reason
/// docs/15 exists.
/// </para>
/// </remarks>
public static class CmcRequest
{
    /// <summary>id-cct-PKIData. The content type of a CMC full PKI request.</summary>
    public const string PkiDataContentType = "1.3.6.1.5.5.7.12.2";

    /// <summary>
    /// Wraps a PKCS#10 in a <c>PKIData</c> and signs it as the enrolment agent.
    /// </summary>
    /// <param name="pkcs10">
    /// DER, signed by the key on the card. Not re-verified here: by the time a
    /// request reaches a backend the attestation has been believed and the
    /// PKCS#10 checked against the attested key - see <c>CertificateRequestContext</c>.
    /// </param>
    /// <param name="bodyPartId">
    /// Identifies this request inside the envelope. Only meaningful when a CA's
    /// answer refers back to it, which with one request per envelope it does not,
    /// so it is fixed rather than configurable.
    /// </param>
    public static Task<byte[]> CreateAsync(
        byte[] pkcs10, IEnrolmentAgentKeyStore agent, uint bodyPartId = 1,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(pkcs10);
        ArgumentNullException.ThrowIfNull(agent);

        if (pkcs10.Length == 0)
        {
            throw new CertificateAuthorityException(
                "There is no certificate request to send. A CMC with an empty body would be "
                + "signed by the enrolment agent and mean nothing.");
        }

        var content = new ContentInfo(
            new System.Security.Cryptography.Oid(PkiDataContentType), PkiData(pkcs10, bodyPartId));

        return agent.SignCmsAsync(content, ct);
    }

    /// <summary>
    /// The <c>PKIData</c> itself: no controls, one tagged certification
    /// request, nothing else.
    /// </summary>
    /// <remarks>
    /// The three empty sequences are not padding. <c>PKIData</c> has four
    /// members and none of them is OPTIONAL, so a CA reading this expects four
    /// sequences and gets them. The template is not among them: it travels in
    /// the attribute string the transport carries, which is how
    /// <c>ICertRequest3</c> and CES both already accept it, and putting it here
    /// as well would be two places to change one name.
    /// </remarks>
    internal static byte[] PkiData(byte[] pkcs10, uint bodyPartId)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);

        using (writer.PushSequence())
        {
            // controlSequence
            using (writer.PushSequence())
            {
            }

            // reqSequence, holding one TaggedRequest
            using (writer.PushSequence())
            {
                // tcr [0], IMPLICIT, so this tag stands in for the SEQUENCE of
                // TaggedCertificationRequest.
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    writer.WriteInteger(bodyPartId);
                    writer.WriteEncodedValue(pkcs10);
                }
            }

            // cmsSequence
            using (writer.PushSequence())
            {
            }

            // otherMsgSequence
            using (writer.PushSequence())
            {
            }
        }

        return writer.Encode();
    }

    /// <summary>
    /// The attribute string that names a template to ADCS.
    /// </summary>
    /// <remarks>
    /// One line, and the name is the template's <b>name</b> rather than its
    /// display name. The two differ on every template anybody has renamed, and
    /// the CA answers a display name with a denial that does not say which of
    /// the two it wanted.
    /// </remarks>
    public static string TemplateAttribute(string templateName) =>
        "CertificateTemplate:" + templateName;
}
