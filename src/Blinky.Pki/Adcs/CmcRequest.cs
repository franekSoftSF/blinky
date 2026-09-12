using System.Formats.Asn1;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Blinky.Pki.Adcs;

/// <summary>
/// A CMC full PKI request carrying somebody else's PKCS#10, in the shape a
/// Microsoft CA accepts on somebody's behalf.
/// </summary>
/// <remarks>
/// <para>
/// This is the whole of "enrol on behalf of". The cardholder's key signed the
/// PKCS#10 on the card, which is the proof of possession; the enrolment agent
/// signs the envelope around it, which is the CA's evidence of <i>who was
/// allowed to ask</i>; and the envelope names <i>who the certificate is for</i>.
/// </para>
/// <para>
/// <b>That last part was missing from the first version</b>, along with half the
/// signatures. It was built from RFC 5272 alone, and MS-WCCE - "Enroll on Behalf of
/// Certificate Request Using CMS and CMC Request Formats" - adds two requirements
/// RFC 5272 does not make. The requester name MUST travel in a <c>RegInfo</c>
/// control as <c>requestername=DOMAIN\user</c>, UTF-8, pairs joined by <c>&amp;</c>;
/// without it the CA has nobody to build the subject for except whoever called it.
/// And the SignedData MUST carry at least two SignerInfos: the enrollee's, or a
/// no-signature one standing in for it, then the enrolment agent's. Microsoft's own
/// annotated certreq request has exactly that shape. Found by reading, before a CA
/// could refuse it.
/// </para>
/// <para>
/// RFC 5272's module is <c>IMPLICIT TAGS</c>, so the <c>[0]</c> on the <c>tcr</c>
/// alternative replaces the SEQUENCE tag of <c>TaggedCertificationRequest</c> rather
/// than wrapping it. Written by hand with <see cref="AsnWriter"/> because .NET has no
/// CMC type, and <c>certenroll</c>'s is COM, which the container cannot call.
/// </para>
/// </remarks>
public static class CmcRequest
{
    /// <summary>id-cct-PKIData. The content type of a CMC full PKI request.</summary>
    public const string PkiDataContentType = "1.3.6.1.5.5.7.12.2";

    /// <summary>id-cmc-regInfo. Where MS-WCCE puts the requester name.</summary>
    public const string RegInfoControl = "1.3.6.1.5.5.7.7.18";

    /// <summary>Body part identifiers, unique within the PKIData as RFC 5272 asks.</summary>
    internal const uint RequestBodyPart = 1;

    internal const uint RegInfoBodyPart = 2;

    private const string Sha256 = "2.16.840.1.101.3.4.2.1";

    /// <summary>
    /// Wraps a PKCS#10 in a <c>PKIData</c> naming the cardholder, and has the
    /// enrolment agent sign it.
    /// </summary>
    /// <param name="pkcs10">
    /// DER, signed by the key on the card. Not re-verified here: by the time a
    /// request reaches a backend the attestation has been believed and the
    /// PKCS#10 checked against the attested key - see <c>CertificateRequestContext</c>.
    /// </param>
    /// <param name="requesterName"><c>DOMAIN\sAMAccountName</c> of the cardholder.</param>
    public static Task<byte[]> CreateAsync(
        byte[] pkcs10, string requesterName, IEnrolmentAgentKeyStore agent,
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
            new System.Security.Cryptography.Oid(PkiDataContentType),
            PkiData(pkcs10, RequesterName(requesterName)));

        return agent.SignCmsAsync(content, ct);
    }

    /// <summary>
    /// A requester name as MS-WCCE takes it, or a refusal naming what is wrong.
    /// </summary>
    /// <remarks>
    /// <c>DOMAIN\user</c> with exactly one backslash. <c>&amp;</c> and <c>=</c>
    /// are refused rather than escaped: they are the separators of the attribute
    /// string, MS-WCCE defines no escape for them, and a name that contained one
    /// would be read by the CA as a different name plus an attribute nobody meant
    /// to send. Neither can appear in a real sAMAccountName or NetBIOS domain.
    /// </remarks>
    public static string RequesterName(string? value)
    {
        var name = value?.Trim() ?? string.Empty;
        var separator = name.IndexOf('\\');

        if (separator <= 0
            || separator == name.Length - 1
            || name.IndexOf('\\', separator + 1) >= 0
            || name.Any(c => c is '&' or '=' || char.IsControl(c)))
        {
            throw new IssuancePolicyException(
                $"\"{value}\" is not a requester name a Microsoft CA can issue for. It has to be "
                + "DOMAIN\\sAMAccountName - the account the certificate belongs to, which the CA "
                + "looks up to build the subject.");
        }

        return name;
    }

    /// <summary>
    /// The <c>PKIData</c>: one <c>RegInfo</c> control naming the cardholder, one
    /// tagged certification request, and the two sequences CMC requires and this
    /// request does not use.
    /// </summary>
    /// <remarks>
    /// The template is not in the <c>RegInfo</c> although it could be. It travels in
    /// the attribute string the transport carries, which is how <c>ICertRequest3</c>
    /// and CES both take it, and two places to change one name is one too many.
    /// </remarks>
    internal static byte[] PkiData(byte[] pkcs10, string requesterName)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);

        using (writer.PushSequence())
        {
            // controlSequence: TaggedAttribute { bodyPartID, attrType, attrValues }
            using (writer.PushSequence())
            {
                using (writer.PushSequence())
                {
                    writer.WriteInteger(RegInfoBodyPart);
                    writer.WriteObjectIdentifier(RegInfoControl);

                    using (writer.PushSetOf())
                    {
                        writer.WriteOctetString(Encoding.UTF8.GetBytes("requestername=" + requesterName));
                    }
                }
            }

            // reqSequence, holding one TaggedRequest
            using (writer.PushSequence())
            {
                // tcr [0], IMPLICIT, so this tag stands in for the SEQUENCE of
                // TaggedCertificationRequest.
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    writer.WriteInteger(RequestBodyPart);
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
    /// Signs a <c>PKIData</c> the way MS-WCCE requires on somebody's behalf: a
    /// no-signature SignerInfo standing in for the enrollee, and the agent's.
    /// </summary>
    /// <remarks>
    /// <para>
    /// No-signature rather than the enrollee's own, because the enrollee's key is on
    /// a card on somebody's desk. MS-WCCE allows either; the card's would cost a
    /// second operation and a second PIN, and is only worth it if a CA refuses this.
    /// </para>
    /// <para>
    /// The connector holds a copy of this, because it deliberately does not
    /// reference <c>Blinky.Pki</c>; a test runs a request through both and
    /// compares the shape.
    /// </para>
    /// </remarks>
    internal static byte[] SignAsAgent(ContentInfo content, X509Certificate2 agent)
    {
        var signed = new SignedCms(content, detached: false);

        signed.ComputeSignature(
            new CmsSigner(SubjectIdentifierType.NoSignature)
            {
                DigestAlgorithm = new System.Security.Cryptography.Oid(Sha256),
            },
            silent: true);

        signed.ComputeSignature(
            new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, agent)
            {
                // The signer certificate and nothing above it. ADCS issued this
                // enrolment agent certificate, so it can build the rest of the
                // chain from its own store.
                IncludeOption = X509IncludeOption.EndCertOnly,
                DigestAlgorithm = new System.Security.Cryptography.Oid(Sha256),
            },
            silent: true);

        return signed.Encode();
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
