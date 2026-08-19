# 04 — PKI backends

Two implementations of one interface, both built from the start. Neither is a
stub, and neither is the "real" one.

- **Built-in CA** — runs in the compose stack, needs no directory, and is the
  only option where there is no ADCS (Samba4, or no AD at all).
- **ADCS** — drives an existing Microsoft CA through an enrolment agent. The
  certificates are issued by the CA the organisation already trusts, which in a
  Windows shop is the only answer that survives a security review.

## The interface

```csharp
public interface ICertificateAuthority
{
    string Backend { get; }                       // "builtin" | "adcs"
    Task<CaCapabilities> DescribeAsync(CancellationToken ct);
    Task<IssuedCertificate> IssueAsync(CertificateRequestContext ctx, CancellationToken ct);
    Task RevokeAsync(RevocationRequest req, CancellationToken ct);
    Task<CrlDocument> GetCrlAsync(string caId, CancellationToken ct);
}

public sealed record CertificateRequestContext(
    byte[] Pkcs10,                    // signed by the card
    AttestationResult Attestation,    // already verified — see 03
    CardholderIdentity Subject,       // UPN, SID, DN, display name
    CertificateProfile Profile);

public sealed record CaCapabilities(
    bool SupportsSuppliedSubject,
    bool SupportsRevocation,
    bool PublishesCrl,
    bool AddsSidExtension,
    IReadOnlySet<string> Algorithms,
    IReadOnlySet<string> ProfileNames);
```

`CaCapabilities` is how the differences leak in a controlled way. The console
greys out what the selected backend cannot do; it does not discover the limit
by failing an issuance in front of a user.

## What a smart-card logon certificate must contain

This applies to **both** backends, and getting it wrong is the single most
common reason a self-built PKI fails at smart-card logon.

| Field | Value |
|---|---|
| Key usage | `digitalSignature` (add `keyEncipherment` for the `9D` profile) |
| EKU | `1.3.6.1.5.5.7.3.2` Client Authentication |
| EKU | `1.3.6.1.4.1.311.20.2.2` Smart Card Logon |
| SAN | `otherName` `1.3.6.1.4.1.311.20.2.3` = the user's UPN |
| Extension | `1.3.6.1.4.1.311.25.2` — the SID extension, see below |
| AIA / CDP | URLs a **domain controller** can reach, not just the client |

The AIA/CDP point is easy to miss in a lab where everything runs on one host.
The DC validates the user's certificate during logon; if the CDP is a URL only
the workstation can resolve, logon fails with an error that says nothing about
DNS.

### Strong certificate mapping

Since the KB5014754 enforcement change, a domain controller will not accept a
certificate for logon on the basis of the UPN alone. It needs either:

- the **SID extension** `1.3.6.1.4.1.311.25.2` in the certificate, carrying the
  user's `objectSid` — the path Blinky takes by default, or
- an explicit `altSecurityIdentities` mapping on the user object, using a strong
  form such as `X509:<I>issuer<SR>serial` — the fallback when the CA cannot be
  made to emit the extension.

Which is why `Cardholder.object_sid` is resolved at onboarding rather than at
issuance. It is also why `CaCapabilities.AddsSidExtension` exists: the built-in
CA always adds it, whereas ADCS adds it only when the subject is built from
Active Directory. **An ADCS template configured with "supply in the request"
will produce certificates without the SID extension**, and those certificates
will not log anybody in. Blinky validates the template configuration when the
ADCS backend is registered and refuses the combination up front.

## Backend 1 — built-in CA

### Two topologies, one interface

The built-in CA runs in either of two shapes, chosen per `CaInstance` at
creation:

```
single                          two-tier
──────                          ────────
CA (self-signed, online)        Root CA (self-signed, offline)
  ├─ smartcard-logon → 9A         └─ Issuing CA (online, in api/worker)
  ├─ signing         → 9C              ├─ smartcard-logon → 9A
  ├─ encryption      → 9D              ├─ signing         → 9C
  └─ card-auth       → 9E              ├─ encryption      → 9D
                                       └─ card-auth       → 9E
```

Both are produced by `scripts/new-ca.sh --topology single|two-tier`, and
nothing above `ICertificateAuthority` can tell them apart: same profiles, same
issuance path, same revocation, same publication into the directory. Only the
chain differs, and the chain is data.

| | `single` | `two-tier` |
|---|---|---|
| Keys online | one — the trust anchor itself | one — the issuing CA only |
| Trust anchor exposed to the network | **yes** | no |
| Recover from a compromised issuing key | re-trust a new anchor on every machine | revoke, issue a replacement from the offline root, clients unchanged |
| Certificates to distribute | one | two, of which one never changes |
| Sensible for | lab, demo, single-site pilot, air-gapped rig | anything whose lifetime is measured in years |

**The honest version of the trade.** `single` is not wrong, it is *cheaper now
and more expensive later*, and the later cost lands in one specific event: the
day the issuing key is compromised or the algorithm has to change. With a
single CA that day means touching the trust store of every machine in the
domain. With two tiers it means one revocation and one new intermediate.

Which is why the default is `two-tier` and `single` is a deliberate answer to a
prompt, not something you get by not reading the documentation.

### Things that differ between the topologies and will bite

**Path length.** In `two-tier` the root carries
`basicConstraints = critical, CA:TRUE, pathlen:0` — it may sign the issuing CA
and the issuing CA may sign nothing but end entities. Omitting `pathlen` is
harmless until somebody quietly signs a third tier; setting it to `0` on the
*issuing* CA instead is a chain that fails validation on some clients and not
others, which is worse than failing everywhere.

**What goes into NTAuth.** This is the one that produces "smart-card logon just
does not work" with no useful error:

| Container | `single` | `two-tier` |
|---|---|---|
| `NTAuthCertificates` | the CA | the **issuing** CA — the one that signed the user certificate |
| `Certification Authorities` / client root store | the CA | the **root** |

Publishing the root into NTAuth in a two-tier setup looks correct, validates by
eye, and does not work.

**CRLs, both of them.** The root's CRL is what revokes the issuing CA. It
changes almost never, which is exactly why it gets forgotten — and an expired
root CRL breaks every chain built under it. The worker regenerates it on a long
schedule and the health endpoint reports the nearer of the two expiries, not
just the issuing CA's.

**Topology is immutable per instance.** Switching an existing `CaInstance` from
`single` to `two-tier` would leave already-issued certificates chaining to an
anchor the instance no longer claims. So it is not allowed: a new topology is a
new `CaInstance`, profiles are repointed at it, and credentials migrate as they
renew. The data model already supports this — profiles name their instance —
and it is the same mechanism that lets ADCS and the built-in CA coexist.

Deeper hierarchies — a policy CA between root and issuing — are out of scope.
Three tiers solve an organisational problem (separate policy domains under one
anchor) that a project of this size does not have, and every tier is another
CRL nobody remembers to renew.

### Key storage, three tiers

| Tier | Where the issuing key lives | For |
|---|---|---|
| `file` | Encrypted PKCS#12 on a volume | Laptop, demo, CI |
| `softhsm` | SoftHSM2 via PKCS#11, in its own container | Compose default, integration tests |
| `pkcs11` | Real HSM or YubiHSM 2 | Production |

All three go through the same PKCS#11-shaped abstraction, so moving from the
compose default to an HSM is configuration, not a rewrite. `file` refuses to
start unless `Blinky:Ca:AllowFileKeys` is explicitly true — the accident to
prevent is a demo profile quietly reaching production.

In `single` topology the online key *is* the trust anchor, so the `file` tier
is refused outright rather than merely gated: a self-signed anchor whose key
sits unencrypted-at-rest next to the process that uses it has no recovery story
at all.

### Issuance

.NET's own `CertificateRequest` and `X509SignatureGenerator` do the signing for
RSA and ECDSA; BouncyCastle is pulled in only where .NET has no answer (CMC
structures, some PKCS#7 handling). The result is less third-party crypto in the
signing path, which is the path that matters.

The profile drives everything: algorithm, validity, EKUs, subject and SAN
templates, and the required PIN and touch policy — the last two are checked
against the attestation before signing, so a profile that demands touch cannot
be satisfied by a token that was provisioned without it.

### Revocation and publication

The worker regenerates the CRL on a schedule and immediately on every
revocation. Both CRL and CA certificates are served as static files by the
`frontend` nginx container under `/pki/`, which means the AIA and CDP URLs are
on the same host as the console and there is no fourth service to run.

An OCSP responder is an optional container. It matters for revocation latency;
it does not matter for a first deployment, where a six-hour CRL is fine and one
fewer moving part is worth more.

### Publishing into the directory

For logon to work the CA has to be trusted by the domain, which means the CA
certificate has to be in the directory:

```
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,<domain DN>
    attribute: cACertificate
CN=<CA name>,CN=Certification Authorities,CN=Public Key Services,...
    attribute: cACertificate
```

On Windows AD this is `certutil -dspublish -f ca.crt NTAuthCA`. Blinky does it
over LDAP instead, so the same code path works against Samba4 — see below.

**Which certificate goes where depends on the topology**, and getting it
backwards is silent: see the NTAuth table above. In `two-tier` the issuing CA
goes into `NTAuthCertificates` and the root into the trusted root container; in
`single` the one certificate goes into both.

## Backend 2 — ADCS via enrolment agent

### The model

Blinky never holds a user's private key and cannot prove the user's identity to
ADCS directly. Instead it acts as a **registration authority**: it holds an
*Enrolment Agent* certificate and signs a CMC request on the cardholder's
behalf. ADCS calls this "enrol on behalf of".

```
card-signed PKCS#10
        │
        ▼
  CMC full PKI request
        │  signed by the Enrolment Agent certificate
        ▼
     ADCS  ── validates RA signature
           ── checks template permissions
           ── builds subject from AD
           ── issues
```

Prerequisites on the ADCS side, all of which Blinky verifies at backend
registration rather than at first use:

- An **Enrolment Agent certificate** for the Blinky service account, from the
  *Enrollment Agent* or *Exchange Enrollment Agent (Offline request)* template.
- A **target template** — typically a copy of *Smartcard User* — with:
  - issuance requirement "This number of authorized signatures: 1",
  - application policy on that signature: *Certificate Request Agent*
    (`1.3.6.1.4.1.311.20.2.1`),
  - subject name **built from Active Directory**, not supplied in the request,
    for the SID-extension reason above,
  - the Blinky service account granted *Enroll* on the template.
- Ideally, **Restricted Enrollment Agents** configured on the CA, limiting which
  users Blinky may enrol on behalf of. Blinky recommends it in the setup check
  and does not require it.

### Two transports, because one of them cannot cross the container boundary

ADCS's native interface is DCOM (`ICertRequest3::Submit`). DCOM from a Linux
container is not a realistic dependency, so:

| Transport | How | When |
|---|---|---|
| **CES/CEP** over HTTPS | MS-WSTEP `RequestSecurityToken` to the Certificate Enrollment Web Service; MS-XCEP to the Policy Web Service for template discovery. Kerberos, client certificate, or username auth | Preferred. Pure HTTPS, works from the container, nothing extra to install on a Windows box |
| **`Blinky.AdcsConnector`** | A small Windows service next to the CA that exposes the same contract over HTTPS and calls `ICertRequest3` locally | For estates that never deployed CES, which is most of them |

Same `AdcsCertificateAuthority` class, two `IAdcsTransport` implementations. The
choice is one configuration value, and the rest of the system does not know
which is in use.

The connector exists for the same reason the agent exists: some interfaces only
work from inside Windows, and pretending otherwise produces a product that
demos well and does not deploy.

### Revocation

`ICertRequest`/CES revoke by serial and reason; CRL publication stays ADCS's
job. `CaCapabilities.PublishesCrl` is false for this backend, and the console
links to the CA's own CDP rather than pretending to own it.

## The Samba4 variant

Samba4 as an AD DC has **no ADCS**. There is no Microsoft CA to talk to, so the
built-in CA is not a fallback here — it is the design.

What is Samba-specific is small, and it is all publication:

1. **Publish the CA into the directory over LDAP.** Same `cACertificate`
   attributes on the same containers as AD, written with an LDAP modify rather
   than `certutil`. Samba's `NTAuthCertificates` object may not exist in a fresh
   provision and is created if missing.
2. **Issue a KDC certificate for PKINIT.** Smart-card logon against a Samba KDC
   is PKINIT, and the KDC needs its own certificate with:
   - EKU `1.3.6.1.5.2.3.5` (KDC Authentication / `id-pkinit-KPKdc`),
   - SAN `dNSName` of the DC,
   - SAN `otherName` `1.3.6.1.5.2.2` (`id-pkinit-san`) carrying
     `krbtgt/REALM@REALM`,
   - installed where the Heimdal KDC expects it, under Samba's private TLS
     directory.
3. **Map the user.** The same SID extension applies; where the Samba version in
   use does not honour it, the fallback is `altSecurityIdentities` on the user
   object, written over the same LDAP connection.

A `blinky-samba-setup` command performs all three against a provided admin bind
and prints what it changed. It is a separate command, not part of normal
startup, because writing to the Configuration NC of a directory is not something
a container should do on boot.

## Choosing a backend

| | Built-in CA | ADCS |
|---|---|---|
| Directory required | No | Yes, Windows AD |
| Works with Samba4 | Yes | No |
| End-to-end in `docker compose up` | Yes | No — needs a CA and a lab |
| Trusted by the domain out of the box | No — publication step required | Yes |
| Supplies the SID extension | Always | Only with subject built from AD |
| Owns CRL / OCSP | Yes | No — ADCS does |
| Key custody | Yours: file, SoftHSM, or HSM | The CA's existing custody |
| Realistic use | Samba4 estates, labs, greenfield, air-gapped | Existing Windows estates |

Both are configured at once in a mixed estate: `CaInstance` rows are per-CA, and
a `CertificateProfile` names the instance it issues from. Nothing prevents slot
`9A` coming from ADCS while `9D` comes from the built-in CA, and in an
organisation migrating between the two, that is exactly what happens.
