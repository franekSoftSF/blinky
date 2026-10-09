# 06 — Security

A credential management system is a machine that turns "this person should have
a certificate" into a certificate the domain trusts. Every interesting attack is
a way of lying to it about one of those two halves.

## Trust boundaries

```
┌─ untrusted ────────────────────────────────────────────────┐
│  The user, the workstation, the token in the reader        │
│  Everything here can be lied about                         │
└────────────────────┬───────────────────────────────────────┘
                     │  mTLS (agent) + Kerberos (user)
┌────────────────────▼───────────────────────────────────────┐
│  api / worker                                              │
│  Decides what may be issued, to whom, and enforces it      │
└────────────────────┬───────────────────────────────────────┘
                     │  PKCS#11                 │  CES / DCOM + EA cert
┌────────────────────▼──────────┐   ┌───────────▼────────────┐
│  HSM: master key, CA key      │   │  ADCS                  │
│  Never exports key material   │   │  Its own trust domain  │
└───────────────────────────────┘   └────────────────────────┘
```

The rule that follows from the diagram: **no authorisation decision is made on
the workstation.** The agent proposes; the API disposes. An agent that has been
fully compromised can still only obtain certificates the policy already allows
for the user whose Kerberos ticket it can produce.

## Threats

| # | Threat | Mitigation |
|---|---|---|
| 1 | Software key presented as hardware-backed | Attestation verified against the pinned Yubico root **before** the CA is called, and the attested public key compared to the key in the CSR. See [03](03-piv-layer.md#enrolment-end-to-end) |
| 2 | Token substituted mid-workflow | Management-key authentication is mutual; every job step re-asserts the serial via `RequireToken` |
| 3 | Enrolment on behalf of someone else | The user's own Kerberos ticket, obtained in their own session, must resolve to the cardholder on the job. Operator override is a distinct, audited path |
| 4 | Compromised workstation issuing to itself | Machine identity (mTLS) proves the machine only. It cannot substitute for the user token |
| 5 | Stolen agent certificate | 90-day lifetime and revocable from the console. Grants only the ability to ask for work, never to authorise it. **Automatic rotation is not built** — see *Claimed and not built* below |
| 6 | Stolen bootstrap token | Single-use, rate-limited, per-deployment, revocable. Buys one agent certificate |
| 7 | Management key extracted from one token | Keys are per-token derived from an HSM-resident master. One token's key opens one token |
| 8 | Database stolen | No PINs anywhere, no management keys (derived, not stored), PUKs encrypted under an HSM-held KEK with the serial as AAD |
| 9 | Orphaned certificate — CA signed, card never received it | The `Issued`/`Installed` split makes it a visible state; the reconciler retries or revokes |
| 10 | Certificate that logs in as the wrong person | SID extension emitted by the built-in CA; the ADCS backend refuses templates configured to supply the subject in the request. See [04](04-pki-backends.md#strong-certificate-mapping) |
| 11 | Silent replacement of a Blinky-issued credential | Inventory compares slot contents against the recorded public-key hash; a mismatch marks the slot `Stale` and raises it rather than overwriting |
| 12 | PUK disclosure by an insider | Every decryption of an escrowed PUK writes an audit event exempt from retention, and is a designed alerting trigger |
| 13 | Browser claiming an agent identity | The edge overwrites `X-Client-Verify` and `X-Client-Cert` with empty values on the console listener; only the mTLS listener sets them from a verified certificate |
| 15 | A passkey provider's credential stolen from the database | Sealed with AES-GCM under a key derived from the PUK KEK in its own domain, the provider's id and credential kind authenticated; generated on the server by default so the private half never reaches a browser; returned by no route. See [13](13-passkey-provisioning.md#configuring-a-provider) |
| 16 | A provisioned key intercepted in transit with its PIN | The provisional FIDO2 PIN is shown once on the workstation and stored nowhere; key and PIN ship by different channels; forced PIN change on first use; revocation deletes at the provider first. See [13](13-passkey-provisioning.md#chain-of-custody) |
| 14 | Denial of service by PIN blocking | PIN retry counters are read on every contact and surfaced before they reach zero; the unblock workflow is deliberately cheap |

## Where the management key and the PUK actually stand

Rows 7 and 8 above describe the design, and the design is now implemented. Two
things about it are worth saying plainly rather than leaving to be discovered.

**The master is in `.env`, not in an HSM.** The derivation is real — HKDF over
the master and the token's serial, nothing written down, one token's key opening
one token — but the master sits beside the database password until the PKCS#11
tier exists. `/api/system/status` reports the custody tier and says
`productionReady: false` for exactly this reason. Row 7's "HSM-resident" is the
destination, not the current state.

**A card is personalised at its first enrolment, and only then.** A card already
holding a management key is left with it, because there is no way to tell a key
this deployment set under an old master from one another deployment set, from
one the YubiKey minidriver set when it took ownership. Replacing it because the
card happened to open would take the card away from whoever owns it.

The consequence is not subtle: **every card issued before this landed still
holds the factory management key and the factory PUK**, and will keep holding
them. Bringing one into the fold means resetting its PIV application, which
destroys the credential on it. That is a decision for whoever runs the
deployment, not something an enrolment should do quietly.

**A deployment with no master configured is a supported state**, not a
misconfiguration — it leaves every card on the factory key, which is where they
all are today. It is visible in the system status rather than silently fine.

## Key custody

Four secrets, in descending order of how bad it is to lose them:

1. **The CA issuing key.** In the HSM in production, SoftHSM in the compose
   default, and a file only when `Blinky:Ca:AllowFileKeys` is explicitly set.
   Compromise means arbitrary certificates the domain trusts.
2. **The enrolment agent key**, where ADCS is the backend. Compromise means
   certificates from somebody else's CA in anybody's name — bounded only by what
   the target template allows and by Restricted Enrollment Agents where the CA
   has them configured. It ranks below the issuing key because the CA still
   enforces the template, and above the master because what it produces is a
   logon identity rather than a card that can be reprogrammed.
3. **The management-key master.** HSM-resident, never exported. Compromise means
   every managed token can be reprogrammed. Its derivation is versioned so
   rotation is a version bump and a job per token, not a fleet rebuild.
4. **The PUK KEK.** Same HSM. Compromise means every escrowed PUK.

The root CA key is not on this list because it is not in the system: generated
offline, used to sign the issuing CA, and stored off the host.

### Where the enrolment agent key lives

`IEnrolmentAgentKeyStore` in `src/Blinky.Pki/Adcs`, and it is a sibling of
`ICaKeyStore` rather than a third `KeyPurpose` behind `IKeyProvider`. That was
the plan until the interface could be read: `IKeyProvider` has exactly one
operation, an HMAC, because both secrets it was built for are key-derivation
roots. An enrolment agent signature is a CMS `SignerInfo` over a CMC, and no
amount of HMAC produces one.

The signature happens behind the interface and there is no way to ask for the
key. **Where the key physically is depends on the transport, and was changed
once on purpose.**

**With the connector, the key lives on the Windows server beside the CA**, in the
integration account's own store, and `ConnectorEnrolmentAgentKeyStore` asks for a
signature over the wire. This section first said the opposite — that the key
never reaches the connector — and that lost on the property that matters most for
this key:

- In a Windows store the key can be **non-exportable**, or in a TPM, and never
  exist as a file. In the container the only tier was a PKCS#12 exported from a
  template that permits export, with its password beside it.
- The CA server is already the most trusted machine in the arrangement. Whoever
  holds it issues what they like, agent or not, so the key adds almost nothing
  there and a great deal in a container.
- Autoenrollment renews it.

Custody is **read off the key, not inferred from where it is.** The connector
reports the key's own export policy and provider, and the container treats an
exportable key, or one whose provider will not say, as not production-ready.
Measured while building it: the same PKCS#12 loaded twice gave one exportable key
and one that was not, depending only on the flag at import. Being on a Windows
server settles nothing.

**What moved with it, and what did not.** The decision did not: the container
still chooses the cardholder and template and builds the `PKIData`. The connector
parses it before signing and refuses anything that is not exactly one PKCS#10
enrolment — no controls, because a control can be a signed revocation; no nested
content; no second request; no request whose own signature fails — and logs the
subject, the key hash and the calling client certificate for every signature it
makes. **The cost:** the client certificate the container uses to reach the
connector now buys this key's signature, and is worth as much as the key.

**With CES there is no Blinky service on the Windows side**, so the key stays in
the container behind `FileEnrolmentAgentKeyStore`, refused unless
`Blinky:Adcs:AllowFileKeys` is set — the same explicit opt-in the CA key has, for
the same reason: nobody decides to keep this in a file, they inherit it from
whatever got the lab working. A PKCS#11 tier for this case does not exist yet.

Both refuse a certificate ADCS would refuse before it is used: outside its
validity dates, or missing *Certificate Request Agent* (`1.3.6.1.4.1.311.20.2.1`).
A certificate carrying no extended key usage extension at all is refused too —
that absence means "unrestricted" for TLS and "not an enrolment agent" to ADCS.
The connector and the container each hold a copy of these rules, and a test runs
the same certificates through both. See [15](15-adcs-connector.md).

## Where the second and third of those actually live

`src/Blinky.Secrets`. One interface, `IKeyProvider`, with one operation on it: a
keyed MAC computed wherever the key is. There is no export, no accessor and no
property returning bytes, and that absence is the design rather than an
oversight — an interface that can return a key is one a device cannot implement,
and then the device tier is a rewrite instead of a line of configuration.

Two providers today and they are the same code path:

| `Blinky:Secrets:Provider` | Where the secret is | For |
|---|---|---|
| `Configuration` | This process's environment | Laptop, demo, CI. The default |
| `Pkcs11` | A token, via a module path | SoftHSM2 today, a device later |

SoftHSM2 is the reference module and nothing in the code knows its name. A
YubiHSM is `Blinky:Secrets:Pkcs11:Module` pointing somewhere else, and the
provisioning is the same four commands.

**Keys are separated by purpose and by generation.** The label is derived, not
configured: `blinky/management-key/v1`, `blinky/puk-kek/v2`. The provider looks
for every generation up to the configured one, so a rotation is a new key beside
the old one rather than a flag day — a card diversified under generation one
stays manageable while generation two is what new cards get, and
`Token.ManagementKeyVersion` records which is which.

**Every key is created sensitive and non-extractable, and this is checked rather
than assumed.** The provider reads both attributes back from the token at start
and refuses a key the device would hand out, because that arrangement has the
interface of a device and the custody of a file and would otherwise report as
the former. `Blinky:Secrets:Pkcs11:RequireNonExportable` turns the check off and
has to be set deliberately, which is the same shape as `AllowFileKeys`.

**Every use is counted and logged, and neither the input nor the output is.**
One line per operation with the label, the input length and the duration; the
running totals are on `/api/system/status`, which is where a device that has
started refusing becomes visible before an enrolment fails.

### The one thing the derivation had to change

HKDF has two halves. Extract computes `HMAC(salt, master)` — the master is the
*message*, not the key — so it cannot be performed by a token holding the master
as a key object. The way out is not to export the master. It is to keep the
pseudorandom key that extract produces as the thing the token holds, which
RFC 5869 §3.3 permits for input that is already uniformly random, and Blinky's
masters are read from a cryptographic source.

The consequence is the good one. For a 32-byte output, HKDF is one HMAC block,
so `HMAC(extract(master), info ‖ 0x01)` is bit-for-bit what
`HKDF.DeriveKey(master, info)` returned before any of this existed. A deployment
moving onto a token imports the extract of the master it already has and **every
card keeps the management key it is holding**. There is a test that pins the
equality, and if it ever fails, every card in every deployment becomes
unmanageable at the next enrolment.

So the migration is:

```
SecretsTool init-token --so-pin S --pin P
SecretsTool import --pin P --purpose ManagementKeyMaster --master $MASTER
SecretsTool import --pin P --purpose PukKek --version 2 --master $PUK_KEK
```

`import` for a deployment with cards in the field; `generate` for one without,
after which nothing outside the token has ever seen the value. Import is the one
moment a secret crosses into the token and it is a step a person runs, not
something the service can do — the API opens a read-only session and cannot
create objects at all.

### The PUK escrow needed a real transition, and did not get away with it

The management-key master was already a derivation root, so it maps onto a MAC.
The PUK KEK was not: it was used directly as an AES-GCM key, which is exactly
the shape a token cannot serve, because using a key as a cipher key means
holding its bytes.

From generation two each envelope gets its own key, derived from the root, the
token the envelope belongs to and the nonce it will be used with. That needs one
operation from the device instead of a cipher mode whose support varies between
providers, and it makes the one mistake AES-GCM does not forgive — the same key
and nonce twice — structurally impossible, because no two envelopes share a key.

`SecretEnvelope.KeyVersion` says which scheme opens a row. **Generation one is
the raw configured KEK and stays readable**, because the alternative is a
migration that strands every PUK escrowed before the upgrade. That means
`Blinky:Puk:Kek` has to stay configured for as long as any generation-one
envelope exists, and the status endpoint says whether it is.

## Passkeys and the network

Phase 7 is the one part of Blinky that reaches a cloud. Only the `api`
container does, only to the Entra or Okta endpoints of a provider an
administrator configured, and only server to server: the agent is told the
relying party, origin and challenge and never calls a provider itself, so a
compromised workstation holds no provider credential and can register nothing
the API did not hand it a challenge for. The API checks the returned
clientDataJSON against the challenge and origin it issued before the provider
sees it. The egress table and the rest are in
[13](13-passkey-provisioning.md#what-leaves-the-network).

## What is deliberately not protected

Stated plainly, because a security section that claims completeness is lying:

- **A user who is present, authenticated and knows their PIN can use their key.**
  That is the product. Blinky governs issuance, not use.
- **An operator with the issuance role can enrol on behalf of anybody in scope.**
  This is required for onboarding and desk-side support. It is constrained by
  role, logged in full, and is the correct thing to alert on — not to remove.
- **The WAF does not protect the agent channel.** It runs there in detection
  mode by design, because a rule set that blocks base64-of-DER blocks
  enrolment. An attacker holding a valid agent client certificate is not
  stopped by pattern matching; they are stopped by the API's schema validation
  and by the user-identity requirement. The alerts are still worth having.
- **A compromised domain controller defeats everything.** Identity comes from
  the directory; if the directory lies, Blinky faithfully certifies the lie.
- **Physical possession plus a known PIN is authentication.** Touch policy
  raises the bar to physical presence per operation; it does not change the
  model.

## How the agent's certificate rotates

Every poll, the agent asks how long its own certificate has left and replaces
it with a month to go. It proves itself with the certificate it already holds —
no bootstrap token, which is what lets that token stay rare, short-lived and
rate-limited.

**Before expiry, never after**, and that is a decision rather than an omission.
The edge verifies client certificates during the TLS handshake, so an expired
one cannot reach the renewal endpoint at all; accepting one would mean
loosening verification for every request in order to rescue the few agents that
slept through a month of warnings. Those re-enrol with a bootstrap token, which
is the price of having been switched off for ninety days.

A fresh key each time, not a new certificate over the old one. Renewal is the
only routine moment a workstation key is replaced, and reusing it would mean
one key living for the life of the machine.

The window is configurable, so somebody will eventually set it wider than the
certificates their backend issues — at which point every certificate is always
due and the agent renews on every poll. Observed doing exactly that, twice in
thirty-one seconds. A certificate less than twelve hours old is therefore not
renewed again, and the log names the setting that is wrong.

## Where the agent's own key lives

In the Windows certificate store, and not in a file. `LocalMachine\\My` —
`certlm.msc` — for a service running as `LocalSystem`, which is right because
the identity belongs to the workstation rather than to whoever is logged into
it. A process running as a person cannot write there without elevation and
falls back to `CurrentUser\\My`, `certmgr.msc`; the agent logs which one it
used, because the same machine run both ways enrols twice and that is
otherwise a mystery.

This replaced a PEM key pair under `%ProgramData%`, and the reason is worth
keeping. A directory created there inherits `BUILTIN\\Users:(RX)` — measured,
not assumed — so every local user on the workstation could read the agent's
client-certificate private key and then speak to the backend as that machine.
An agent identity is what the API checks before it will discuss a token at all.

The key is imported without `Exportable`, so it cannot be read back out — not
by the agent, not by anything running as the same account. Verified: an export
attempt is refused by CNG. What an attacker on the machine can still do is
*use* it while they are on the machine, which is a materially smaller thing
than walking away with it. Recovery from a lost key is re-enrolment.

The directories that remain under `%ProgramData%` — the log, and the
file-based identity that non-Windows builds still use — are created with
inheritance off and an explicit list: `SYSTEM`, `Administrators`, and the
account running.

## What the WAF costs, measured

The console listener runs CRS in blocking mode, and that is worth what it costs
— but the cost is real and shows up in ordinary places, not in attacks.

**CRS 930120 (LFI, "OS File Access Attempt") matches on argument *names*.** The
rule tests each name against `lfi-os-files.data`, which lists Unix dotfiles —
including `.profile`. A JSON body with a field called `profileName` arrives as
`ARGS_NAMES:json.profileName`, `PmFromFile` matches on substring, and the
anomaly score crosses the threshold: every certificate-profile request is a
403, from a rule about reading `/etc/passwd`.

Renaming does not escape it. `profile`, `profileName`, `certProfile` — anything
where `profile` follows a dot in the JSON path matches equally.

What is in the repo is one target removed from one rule on two endpoints:

    ctl:ruleRemoveTargetById=930120;ARGS_NAMES:json.profileName

The rule stays on for those endpoints, and `ARGS` — the values, where a real
path traversal would live — stays inspected. The alternatives were worse: turn
the rule off, drop the endpoint out of the WAF, or rename a field in the public
API to dodge a pattern that would still match the next name someone picked.

The general lesson is the one worth carrying: **a blocking WAF in front of a
JSON API will eventually 403 something legitimate, and the first symptom is an
error the application never logged, because the request never reached it.**
Check the edge before debugging the API.

## Hardening not in v1

Tracked, not built, and named here so nobody assumes otherwise:

- OCSP responder (CRL only at first).
- SCP03/SCP11 secure channel to the token, which would protect the management
  key against a compromised host between agent and reader. Firmware-dependent
  and needs verification on the target hardware before it is promised.
- Dual control for issuance — two operators for privileged profiles.
- Tamper-evident audit chain (hash-linked events).
- FIPS-mode token enforcement as a policy condition.
