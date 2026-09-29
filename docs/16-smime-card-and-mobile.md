# 16 — S/MIME on the card, and the same mailbox on a phone

Written before any of it is built. Nothing in this document is implemented:
Blinky today issues `smartcard-logon` and `client-auth`, both onto `9A`, both
ECC P-256, and neither can sign or decrypt a message. What is here is the
direction, the places it collides with rules already written, and the two
things only a tenant can answer.

The trigger was a question — can Blinky feed Omnissa Workspace ONE PIV-D
Manager on Android and iOS — and the answer turned out to be "not through
PIV-D Manager, and not before the card itself can do S/MIME".

## Two halves that behave nothing alike

**Signing** is per device without harm. A recipient verifies with the
certificate attached to the message, so a phone holding its own signing key
and its own certificate produces signatures every client accepts.

**Decryption** is not. A sender encrypts to whatever certificate they find for
the recipient — the directory, or the last signed message — and that is the
card's `9D` certificate. A phone can read that message only if it holds **the
same private key**, and a message from last year only if it holds last year's
key as well (`82`–`95`, see [03](03-piv-layer.md)).

So "derived credential" in the SP 800-157 sense — a fresh key on the device,
bound to the PIV identity — solves signing and authentication and does nothing
for encrypted mail. Mail on a phone needs the encryption key to exist somewhere
other than the card. That is escrow, which is 0045a, and it was needed anyway:
a key that only ever lived on a card makes every message encrypted to it
unreadable the day the card is lost.

## Why not PIV-D Manager

Checked against Omnissa's documentation and one support answer, September 2026.

- **Blinky cannot be a provider.** The provider list is compiled into the app
  (`PIVDProvider`: Entrust, Intercede, Purebred, Xtec, Workspace ONE UEM,
  YubiKey, AuthentX, Thales). The Entrust and Intercede back-end connectors are
  not public.
- **The YubiKey provider is useless for mail on Android.** An Omnissa employee
  confirmed on the community forum (November 2025) that on Android PIV-D only
  shows the YubiKey certificate's metadata; the key never leaves the token and
  cannot be shared with Boxer, so Android gets PDF signing and nothing else. On
  iOS the same token works through CryptoTokenKit — every message a tap.
- **The Workspace ONE UEM provider issues its own key** from a CA configured in
  UEM. That is a correct derived credential for signing and authentication, and
  by the argument above it cannot decrypt a message sent to the card. It also
  leaves Blinky with no record of the certificate, so revoking the card revokes
  nothing on the phone.

What Workspace ONE does have is a path built for exactly this — S/MIME
certificates *with their private keys* delivered to Boxer, the native mail
client and Outlook through a user profile. That is the route below.

## The shape

```
                    ┌──────── card (YubiKey) ─────────┐
 on-card, attested  │ 9C  smime-signing               │  Outlook on Windows
 escrowed, imported │ 9D  smime-encryption  (current) │  signs and decrypts
                    │ 82… smime-encryption  (retired) │  through the minidriver
                    └─────────────────────────────────┘
                                   │ same keys, from escrow
                                   ▼
 Blinky ── uploadsmimecerts ──► Workspace ONE UEM (SaaS) ── profile ──► Boxer / Mail
          encryption: current + every archived generation, from escrow
          signing:    smime-signing-mobile, its own key, not kept by Blinky
```

### Decisions

| Decision | Choice | Why |
|---|---|---|
| Where the encryption key is born | Centrally, in the backend, escrowed before issuance (0045a) | The only arrangement in which a lost card and a second device can both read old mail. Attestation cannot apply and the profile says so explicitly — see below |
| Where the card's signing key is born | On the card, attested, never escrowed | A signing key somebody else holds a copy of cannot support non-repudiation. The card keeps the one signature nobody else could have made |
| The phone's signing key | Its own certificate, `smime-signing-mobile`, key generated centrally, handed to UEM and **not kept** by Blinky | The phone needs to sign and must not get the card's `9C` key, which does not exist off the card. The key passed through UEM, so the profile carries `digitalSignature` without `nonRepudiation` and says so in its name |
| The algorithm in `9D` | RSA 2048 by default | Encryption has to work in the sender's client, not ours. ECC S/MIME in Boxer, iOS Mail and Outlook mobile has not been measured here; RSA works in all of them. P-256 becomes a choice once measured |
| Delivery to the phone | UEM REST `uploadsmimecerts` first; Credential Escrow Gateway as the later option | The upload works on a SaaS tenant today with nothing but an API client. CEG keeps the keys out of UEM but needs Omnissa Professional Services engaged, and Blinky would still have to build the webhook and the certificate provider it expects. The cost of the upload path is written below, not hidden |
| One escrow for both CA backends | Blinky's, even behind ADCS | ADCS key archival would make recovery depend on KRA holders on one backend and on Blinky on the other. The ADCS encryption template must therefore **not** require archival, or the CA will demand the key inside the request |
| PIV-D Manager | Not used for mail | The three reasons above. It remains the right tool for a device authentication credential, which is a different feature |

### Attestation, and the exception to it

Issuance today refuses a request whose key does not match the card's
attestation, and that rule is the reason Blinky can say a key is on hardware.
An imported key cannot be attested — the YubiKey attests only keys it
generated — so `smime-encryption` would be refused by construction.

The exception is **a property of the profile, never of the slot**:
`KeyOrigin = CardGenerated | Escrowed`. An `Escrowed` profile replaces the
attestation check with a different one of equal weight: the public key in the
request must match an escrow envelope Blinky created for that cardholder before
the CA was called. Inferring the exception from `9D` would let a future profile
that meant to be attested skip the check silently; a profile flag is a line in
a review.

### The private key's journey to the card

The one place in the product where a private key crosses the wire, so it is
spelled out.

1. The backend generates the key, seals it in a `SecretEnvelope` under a
   purpose-separated key the `IKeyProvider` holds (the PUK envelope's scheme,
   its own purpose, AAD = cardholder id and envelope id), and issues the
   certificate.
2. The enrolment step names the envelope, **not the key**. The job envelope,
   `jobs.result` and every log carry an id and nothing else — the rule that
   `VERIFY` bytes are a PIN applies here with a private key in place of a PIN.
3. The agent fetches the key once, over its mTLS listener, from an endpoint
   that serves each envelope to one job on one agent and records a disclosure
   event.
4. `IMPORT ASYMMETRIC KEY` (`INS FE`) runs under the authenticated management
   key, and the buffer is zeroised. `0xFE` is added to
   `ApduRedaction.CarriesASecret` **before** the first import is ever sent,
   with a test beside the existing ones.

Without SCP11 the key is in the clear between the agent's memory and the card.
SCP11 is on the *Later* list in [07](07-roadmap.md); this is the first feature
that would use it.

### Every copy is a disclosure

A decrypted envelope leaving the backend is audited like a PUK: actor, reason,
target. The reasons are a closed set — `import-to-card`, `delivered-to-mdm`,
`recovery` — and a delivery to UEM counts once per upload, including the
archived generations it re-sends.

## Workspace ONE UEM, the parts that are known

From Omnissa's documentation and community answers from Omnissa staff. **None of
it has been exercised from here yet**, and 0097's definition of done is where it
gets checked.

- `POST /api/system/users/{id}/uploadsmimecerts` takes PKCS#12 for signing,
  encryption and archived certificates for one enrollment user.
- **There is no API that reads them back.** Every upload replaces what was
  there, so a delivery that omits an archived generation deletes it from the
  device. Blinky must send the whole history every time — which it can, because
  it holds the history in escrow.
- The archived parameter is marked as unsupported in the API reference and
  works; this is a staff answer, not documentation, and is the first thing to
  test.
- A user profile with a credentials payload must be assigned; it sits pending
  until a certificate exists for the user. The upload does not reach a device
  without that profile.
- Event notifications (device enrolled) are the trigger for a first delivery;
  issuance, renewal and `9D` rotation are Blinky's own triggers.
- The enrollment user has to exist in UEM already — synced from the directory
  by the tenant's own connector, not created by Blinky.

**What the upload path costs.** The escrowed encryption key — every generation —
and the phone's signing key sit at rest in Omnissa's SaaS database. Blinky's
escrow is under an HSM-held key; UEM's is under whatever Omnissa does. That is
a real reduction and it is a decision for the owner of the data, not a
technical detail. Credential Escrow Gateway is the answer if it is not
acceptable.

## Data model changes

- `Cardholder.Mail`, read from the directory `mail` attribute at onboarding,
  like `objectSid` and for the same reason: a missing address should fail
  onboarding, not the first S/MIME issuance. Goes into the RFC 822 SAN.
- `CertificateProfile.KeyOrigin`.
- `Credential` today requires a `Token`. The phone's signing certificate has no
  token, so a credential gains a `Cardholder` and a container —
  `Token | MdmUser` — with `Token` null for the second. Still history:
  created and transitioned, never deleted.
- `MdmIntegration` — tenant API URL, token URL, OAuth client id, the secret by
  reference to an envelope, organisation group. Configuration, so **full CRUD
  in the panel** in the same change, with the secret write-only.
- `MdmDelivery` — one row per upload: which credentials and generations, when,
  the response. History, create-only.

## A defect this found

`BuiltInCertificateAuthority` sets `keyEncipherment` on anything issued to
`9D`, whatever the key. For an RSA key that is right. For an EC key it is
wrong: ECDH decryption needs `keyAgreement`, and a strict client refuses to
encrypt to a P-256 certificate that lacks it. Nothing issues to `9D` today, so
nothing is broken yet; the key usage becomes a function of profile and
algorithm in 0094, and [04](04-pki-backends.md) now says so.

## What decides whether this is done

The phase gate in [07](07-roadmap.md#phase-9--smime-on-the-card-and-on-the-phone),
and in particular a message **encrypted to the card before the phone was
enrolled**, read on the phone. Signing on both is easy to demonstrate and
proves almost nothing about the design.

## Open questions

1. **Keys at rest in UEM SaaS — acceptable?** If not, Credential Escrow Gateway,
   which starts with a conversation with Omnissa rather than with code.
2. **How do senders find the encryption certificate?** Outlook looks in the
   directory. On-premises Exchange reads `userCertificate` — Blinky's write
   path for it is 0035, deferred and off by default. Exchange Online gets it
   through directory sync. Without either, encryption works only after the
   recipient has sent a signed message first. Which mail system the lab has
   decides this.
3. **Removal on termination.** Whether UEM can withdraw uploaded S/MIME
   certificates through the API, or only by removing the profile, is not
   documented. 0043's terminate flow needs the answer.
4. **An iOS device.** The Android half can be tested on a managed Android in
   Device Owner mode; nothing here records an iOS device enrolled in the
   tenant.
5. **ECC for S/MIME.** Measure Boxer, iOS Mail and Outlook mobile against a
   P-256 `9D` certificate before offering it.
