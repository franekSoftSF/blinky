# Project status — Blinky

**Last updated:** 2026-08-20
**Phase:** 1 — See the token, gate met. Phase 2 next
**Overall:** the agent reads tokens correctly and reports them; nothing is
issued yet

The machine-readable version of this file is [status.json](status.json). Keep
both in sync; `status.json` is the one a build or dashboard should read. The
definitions of done live in [07 — Roadmap](07-roadmap.md); what is done lives
here.

## Where the project stands

Blinky can see a token and tell the truth about it. An agent enrols itself over
mTLS, watches the readers, and reports what it finds; the backend classifies it
and stores it. Four YubiKeys, two cards from another vendor and a virtual
reader all come out the far end correctly, and no code has written a byte to
any card.

Nothing is issued yet. That is Phase 2, which starts with the certificate
authority interface and the built-in CA — the first patch after which the
system does something for a cardholder rather than about one.

## Validated on hardware

Every rule that came out of a measurement, with its evidence and where it now
lives, is indexed in
[08 — What the hardware changed](docs/08-hardware-notes.md). What follows is
the state of the bench rather than the doctrine.

`tools/PivProbe` is a read-only spike that answers the riskiest question before
any production code exists. Run against a YubiKey 5 on 2026-08-19:

| Question | Answer |
|---|---|
| Does PC/SC with hand-rolled PIV APDUs work? | Yes. SELECT, GET VERSION, GET SERIAL, GET DATA, GET METADATA and the empty-VERIFY retry probe all behave as documented |
| Does the installed HID ActivClient minidriver contend for the card? | No. `SCARD_SHARE_SHARED` plus `SCardBeginTransaction` acquired cleanly with ActivClient present for both YubiKey 5 and YubiKey FIPS |
| Is the 3DES / AES-192 management-key split real? | Yes. Firmware 5.4.3 reports a **3DES** management key, still at its default. The fallback logic in doc 03 is not theoretical |
| Can the card be asked about its own state? | Yes on 5.3+. `GET METADATA` returned PIN, PUK and management-key defaults and retry counters without touching anything |
| Do virtual readers get in the way? | They appear in the reader list — "Windows Hello for Business" answers SELECT PIV with `6A82`. The agent must skip them, not fail on them |

Re-run on 2026-08-19 against three tokens at once, which is when the split the
design assumes stopped being a claim from a datasheet:

| Serial | Firmware | Management key | PIN | PUK |
|---|---|---|---|---|
| 23673995 | 5.4.3 | **3DES**, default | default, 3/3 | default, 3/3 |
| 29177301 | 5.7.1 | **AES-192**, default | default, 3/3 | default, 3/3 |
| 32140892 | 5.7.2 | **AES-192**, default | set, 8/8 | **none — Bio MPE** |

Two findings worth more than the table:

- The 3DES / AES-192 boundary is exactly where the documentation puts it, on
  two independent 5.7 devices and one 5.4. An agent that assumes either
  algorithm fails on a third of this desk.
- **One of them is a Bio Multi-protocol Edition, and it has no PUK by design.**
  Token 32140892 answers `GET METADATA 96` with fingerprints enrolled and three
  match attempts remaining; the other two answer `6A88`. Its missing PUK is the
  factory state of that product line, not a misconfiguration — so "refuse
  tokens without a PUK" as a blanket default would refuse an entire product
  line. The rule distinguishes the two cases; see the decisions below.

On 2026-08-20 the 5.7.1 was provisioned with `ykman` — an ECC P-256 key and a
self-signed certificate in slot `9A` — which closed the second half of patch
0011's definition of done:

| What it proved | Evidence |
|---|---|
| A certificate is read off a card and parses | `9A` reports `CN=blinky-test`, ECC-256 |
| Slot metadata matches what was written | `key=EccP256 origin=Generated pin=Once touch=Never`, read from the card rather than inferred from the certificate |
| **`61xx` chaining works on hardware** | `613D` then `00C000003D`: 256 bytes, then the 61 the card said were left |
| Attestation is reachable | 601 bytes, issuer `CN=Yubico PIV Attestation`. Parsing and chain verification are patch 0012 |

Chaining had until then existed only in hand-built cases — every response from
a blank token fitted a single APDU.

The probe records an APDU transcript, which is the fixture the `Blinky.Piv`
unit tests replay in patch 0010. Transcripts contain the token serial and any
certificate on the card and are **not** committed — `out/` is ignored.

On 2026-08-20, attestation was verified end to end against the pinned Yubico
root:

```
attestation   trusted
  intermediate CN=Yubico PIV Attestation
  issued by    CN=Yubico PIV Root CA Serial 263751
  firmware     5.7.1
  device       29177301   UsbCKeychain
  key policy   pin=Once touch=Never
```

Two things the hardware settled that reading a specification would not have:

- **The intermediate is different on every device.** Three tokens produced
  three `CN=Yubico PIV Attestation` certificates with three different serial
  numbers, all issued by the same root. Only the root can be pinned; the
  intermediate is untrusted input read from the card and has to be verified,
  not assumed. Pinning an intermediate would produce code that works on the
  token it was written against and fails on every other one.
- **The attestation extensions live under `1.3.6.1.4.1.41482.3`, not `.13`.**
  This document set had the wrong arc, the code inherited it, and the verifier
  rejected a genuine token as "not an attestation". The numbers within the arc
  are 3, 7, 8, 9 — not sequential, not guessable.

On 2026-08-20 the agent ran against four tokens at once and the database
agreed with the cards:

| Serial | Firmware | Form factor | State | PUK | Slot 9A |
|---|---|---|---|---|---|
| 23673995 | 5.4.3 | — | Detected | Default | Empty |
| 24031448 | 5.4.3 | — | Detected | Default | Empty |
| 29177301 | 5.7.1 | UsbCKeychain | **Registered** | Default | **Stale** |
| 32140892 | 5.7.2 | — | Detected | **NotApplicable** | Empty |

Three things in that table are the design working rather than data:

- Only 29177301 is `Registered`, because only it holds a key that can be
  attested. Everything else stays `Detected` until it can prove it is genuine
  hardware.
- The form factor is blank on three of four, correctly: it exists only inside
  an attestation, so a blank token simply has none. Reading it from a model
  name would have filled the column with a guess.
- The certificate `ykman` wrote is `Stale`, not `Provisioned`. Blinky did not
  put it there, and every token that has ever been touched by hand looks like
  this.

## Decisions locked

| Decision | Choice | Why |
|---|---|---|
| Runtime | .NET 10 | Same stack as the rest of these projects |
| Token access | PC/SC + raw PIV APDUs | No native library to deploy, no CLI output to parse, full access to the administrative commands a CMS needs. Validated on hardware before the decision was locked — see above |
| Foreign PIV cards | Recognised by asking for a serial, reported as unsupported with a reason | Another vendor's card selects the PIV applet perfectly well. It has no serial, so it has no identity in this model - but silence looks exactly like a broken agent |
| Token scope | YubiKey 5, PIV applet | Attestation and management-key policy are vendor-specific; other vendors are a later interface, not a v1 branch |
| CA backends | Built-in **and** ADCS, one interface, both from the start | Neither is optional: Samba4 has no ADCS, and a Windows estate will not accept a new CA |
| Built-in CA crypto | .NET for signing, BouncyCastle only for CMC/PKCS#7 | Less third-party crypto in the path that matters |
| CA key custody | PKCS#11 abstraction, three tiers: file, SoftHSM2, HSM | Compose default is real PKCS#11; production is a config change, not a rewrite |
| Built-in CA topology | `single` or `two-tier`, per CA instance, default `two-tier` | A single self-signed CA is the right answer for a lab and the wrong one for anything long-lived; both are supported rather than argued about. Topology is immutable per instance — changing it is a new instance, not an edit |
| Management key | Per-token, HKDF-derived from an HSM-held master | One token's key opens one token; the database holds no key material |
| PIN | Never stored, anywhere, in any form | If a workflow appears to need a stored PIN, the workflow is wrong |
| PUK | Random per token, escrowed AES-256-GCM under an HSM KEK | Unblocking has to work over the phone; disclosure is audited and alertable |
| Attestation trust | Only the Yubico root is pinned, embedded with its SHA-256 checked at load; the intermediate is read from the card and verified | The intermediate differs per device — measured on three tokens |
| Bio Multi-protocol tokens | First-class target, detected by asking slot `96`, never by model name | Verification is a fingerprint, not a PIN, and the absence of a PUK is by design. Treating it as a broken normal token would reject the product line |
| Non-Bio tokens without a PUK | Refused at personalisation unless policy `AllowUnrecoverableTokens` is set | Somebody removed the recovery path and nobody recorded why. The first blocked PIN then destroys a credential with no warning anyone gave |
| Transport | HTTPS REST + SignalR doorbell, no broker | One port, one certificate, one auth model; the doorbell carries no state |
| Edge | nginx + ModSecurity 3 + CRS v4, in the container that will also serve Angular | A WAF that adds no box to the diagram |
| WAF on the agent channel | `DetectionOnly`, no body inspection on DER-carrying endpoints | Measured: blocking mode treats base64-of-DER as an attack. mTLS and schema validation are the control there; the WAF is a sensor |
| Client certificate | Verified at the edge, forwarded as a header, stripped on the console listener | The API never terminates TLS, and a browser cannot claim an agent identity |
| Where mTLS is enforced | Edge asks (`optional`), API requires | Requiring at the edge refuses the handshake before enrolment can happen, and only the database knows whether a certificate still belongs to a live agent |
| Agent CA | Separate from the credential CA | "This machine is in the fleet" is a much weaker claim than "this person holds this key on hardware" |
| Bootstrap token | Per deployment, constant-time compared, audited, rotatable | Per-machine tokens are not shippable in an MSI; the token buys an identity, never an authorisation |
| Agent shape | LocalSystem service + per-session UI process | Session 0 cannot draw a PIN prompt, and LocalSystem cannot prove who is at the keyboard |
| Identity | Agent = mTLS, user = Kerberos from the user's own session | No authorisation decision is made on the workstation |
| Store | PostgreSQL + NHibernate | Same as FAG, including the SQL schema script and `SchemaValidator` |
| Schema authorship | Generated from the mappings by `tools/SchemaTool`, never hand-written | Otherwise `SchemaValidator` compares two things that drift apart on the first change. A CI test fails when the committed file stops matching |
| `jsonb` binding | A `JsonbType` user type, not just a column type | Measured: declaring the column alone produces a schema that validates and an insert that fails with `42804` |
| Console | Angular 22 behind nginx, `/api` proxied | One origin, no CORS, same bundle in every environment |
| Docs language | English | Open source, matches CredLoop and NanitorBridge |
| Licence | Apache-2.0 | Patent grant; NHibernate stays a dynamically linked NuGet dependency |

## Decisions deferred

| Question | Blocks | Owner |
|---|---|---|
| CES configuration for enrol-on-behalf-of | Phase 3 (0031) | needs lab test |
| Whether the built-in CA becomes its own container | Phase 2 (0021) | revisit at the PKCS#11 tier |
| Offline desk-side unblock with a pre-fetched PUK | Phase 4 (0042) | security decision, not technical |
| CLI-first v1 instead of the Angular console | Phase 5 | revisit if Phase 2 runs long |
| Which HSM in production | Phase 6 (0062) | needs site input |

Full context in [07-roadmap.md § Open questions](07-roadmap.md#open-questions).

## What each state means

| State | Meaning |
|---|---|
| **done** | Written, tested, and proved against hardware or a running stack |
| **done, unverified** | Written and unit-tested, but one specific claim has no evidence yet. The gap is named in *Implemented but not verified* below |
| **open** | Not started |
| **blocked** | Cannot be done here, with the reason |
| **deferred** | Deliberately postponed, with the patch it waits for |

Nothing is marked done because the code exists. It is done when the definition
of done in [07 — Roadmap](07-roadmap.md) can be checked by somebody who did not
write it.

## Patch progress

### Phase 0 — Design — **complete**

| # | Patch | State | Proof |
|---|---|---|---|
| 0000 | Read-only hardware spike, `tools/PivProbe` | **done** | Ran against five cards; findings in [08](08-hardware-notes.md) |
| 0001 | Architecture and design documents | **done** | Nine documents |
| 0002 | Solution skeleton, central packages, CI | **done** | CI green on windows-latest |
| 0003 | Compose stack and the edge (nginx + ModSecurity + CRS) | **done** | 13 smoke checks |
| 0004 | The stack runs on a machine that is not localhost | **done, unverified** | Certificates carry lab hostnames, the agent pins a CA, `BLINKY_HOST` points the checks elsewhere. Verified against a one-machine stack; the lab it is for does not exist yet |

### Phase 1 — See the token — **gate met**

| # | Patch | State | Proof |
|---|---|---|---|
| 0010 | `Blinky.Piv`: transport, transactions, chaining, error map | **done, unverified** | Replay of a real capture plus hardware through the probe. `6Cxx` and outbound chaining have never run on a card |
| 0011 | PIV read path | **done** | Four tokens read correctly; `61xx` chaining exercised by a real certificate |
| 0012 | Attestation, verified to a pinned Yubico root | **done, unverified** | A genuine token verifies on hardware. Every rejection path is synthetic |
| 0013 | Domain, NHibernate mappings, generated schema, `SchemaValidator` | **done** | Clean validation in both containers; `jsonb` round trip against PostgreSQL |
| 0014 | Agent enrolment over mTLS, agent CA, heartbeat | **done** | Enrolled twice, one row, certificate used |
| 0015 | Agent service and the inventory job | **done** | Four tokens in the database within one poll |
| 0016 | Bio Multi-protocol | **done, unverified** | State reads correctly on a real Bio. The temporary-PIN encoding is unconfirmed — asking for one consumes a match attempt, and nothing needs it until 0027 |
| 0017 | pcsc-lite interop, so the agent runs on Linux | **blocked** | No Linux machine with a reader here. Writing marshalling nothing can test would put untested code under everything else |
| 0018 | `Agent.Ui`, the session 0 split and the named pipe | **done** | The pipe is driven from both ends in tests, and the window was run and typed into: a seven-character PIN accepted, range-checked and discarded. Two bugs found by running it that no test could have caught |
| 0019 | Cards that are not YubiKeys are recognised, not ignored | **done** | An HID Crescendo and a C4000 named and skipped, not dropped |

### Phase 2 — Issue something — **in progress**

| # | Patch | State | Proof |
|---|---|---|---|
| 0020 | `ICertificateAuthority`, `CaCapabilities`, profiles | **done** | Both topologies issue through one interface; capabilities describe the difference |
| 0021 | Built-in CA: generation script, key tiers | **done, unverified** | `scripts/new-ca.sh` builds both shapes and the chains verify. The SoftHSM key tier is not written — only `file`, and it refuses without an explicit opt-in |
| 0028 | Built-in CA topology: single or two-tier | **done** | Chain validates in both; `pathlen` asserted so the reversal cannot return |
| 0022 | Certificate profiles, smart-card logon extensions, SID extension | **partly done** | EKUs, UPN SAN and the SID extension are issued and asserted. The profile model still lives in code rather than in the database |
| 0023 | Key generation, on-card CSR signing, attestation-gated submission | **done** | Proved on two tokens: management key authenticated mutually (AES-192 and 3DES), key generated, attestation verified, card signed its own request |
| 0024 | Certificate write-back, `Issued`→`Installed`, store refresh | **done, unverified** | 1019 bytes written and read back identical, which also ran outbound chaining for the first time. The certificate does **not** reach the Windows store on this machine: ActivClient owns the minidriver binding |
| 0025 | Personalisation: management key, PUK escrow, PIN policy | **open** |
| 0026 | Job engine: leases, watchdog, `AwaitingUser` | **done, unverified** | An operator creates a job, the agent claims it on a lease, runs it and reports; an expired lease is returned to the queue by the watchdog. `AwaitingUser` has its own longer lease but nothing raises it until 0018 |
| 0027 | Biometric user verification during enrolment | **open** |

### Phases 3 to 6 — **open**

ADCS (0030–0034), the lifecycle (0040–0045), the console (0050–0054) and
shipping (0060–0063). None started; definitions of done in
[07 — Roadmap](07-roadmap.md).

## Implemented but not verified

The honest list. Each of these is written and unit-tested, and none has been
exercised against the thing it is really for.

| What | Why not yet | When it gets proved |
|---|---|---|
| `6Cxx` retry-with-length | Comes from T=0 readers; every reader here negotiated T=1 | Needs a T=0 reader, or stays covered by hand-built cases |
| Attestation rejection paths | Forgeries, wrong roots and serial mismatches are synthetic — a real one would mean a counterfeit token | Stays synthetic; the genuine path is proved on hardware |
| The Linux transport | No Linux machine with a reader | 0017 |
| Bio temporary PIN | Requesting one consumes a match attempt and needs a finger | 0027 |
| The SoftHSM key tier | Needs Pkcs11Interop and a container; the `file` tier proves the rest | The other half of 0021 |
| That an issued certificate actually logs anybody in | Needs a domain | The Phase 2 gate, [09](09-lab.md) |
| That a written certificate reaches the Windows certificate store | HID ActivClient owns the minidriver binding on this machine | A clean Windows client, [09](09-lab.md) |
| Multi-machine deployment | The lab is being built; everything so far ran on one box | The lab, [09](09-lab.md) |
| ADCS, CES and the connector | No Windows AD lab yet | 0030–0034 |
| Samba4 publication and PKINIT | No Samba4 provision yet | 0061, and the Phase 2 gate |

## Component progress

| Component | State | Notes |
|---|---|---|
| Architecture docs | **done** | Nine documents |
| `Blinky.Piv` | **done** | Transport, read path, attestation. Drives the probe against real tokens |
| `Blinky.Contracts` | **done** | Protocol version, job enums, inventory contracts |
| `Blinky.Domain` | **done** | Eleven entities from doc 02 |
| `Blinky.Infrastructure` | **done** | Mappings, generated schema, `SchemaValidator` |
| `Blinky.Api` | **partial** | Enrolment, heartbeat, inventory. Issuance from 0023 |
| `Blinky.Worker` | skeleton | Hosts and logs; the job engine is 0026 |
| `Blinky.Agent.Service` | **partial** | Enrols, watches readers, reports. Executes jobs from 0026 |
| `Blinky.Agent.Ui` | **deferred** | Patch 0018 |
| `Blinky.Pki` — built-in CA | **partial** | Issues, revokes, publishes a CRL, both topologies. SoftHSM tier outstanding |
| `Blinky.Pki` — ADCS | open | 0030–0033 |
| `Blinky.AdcsConnector` | skeleton | 0032 |
| Angular console | open | Phase 5 |
| `blinky-samba-setup` | open | 0061 |
| `tools/PivProbe` | **done** | Read-only, drives `Blinky.Piv` against hardware |
| `tools/InsProbe` | **done** | Asks a card whether it knows an instruction, with a control |
| `tools/SchemaTool` | **done** | Generates the schema; `--roundtrip` proves it can be written to |
| `tools/AgentEnrol` | **done** | The whole enrolment flow; run twice by the smoke test |


## Risks being carried

| Risk | Impact | Current handling |
|---|---|---|
| PIV APDU layer misbehaves on real firmware in ways no emulator shows | Phase 1 redesign; everything downstream is blocked | Reduced by 0010: the probe runs on `Blinky.Piv` and produced byte-identical output on all three tokens. Hardware suite from 0011; `yubico-piv-tool` as an independent oracle |
| `6Cxx` and outbound chaining are untested on hardware | A T=0 reader, or the first certificate write, could fail in the field | Neither capture contains them: `6Cxx` needs a T=0 reader and outbound chaining needs a write. Hand-built cases cover both; the first real write lands in 0024 |
| The agent cannot run on Linux | Narrows deployment to Windows | Named, not hidden: `PcscContext.IsSupported`, an explicit exception, and patch 0017 |
| Management-key algorithm differs across firmware (3DES before 5.7, AES-192 after) | Personalisation fails on part of the fleet | Read `GET METADATA`, fall back once, record `Unknown` rather than guessing |
| ADCS template supplies the subject in the request, so no SID extension is emitted | Certificates issue cleanly and then fail to log anybody in | Backend registration refuses the combination up front (patch 0033) |
| CDP or AIA unreachable from domain controllers | Smart-card logon fails with an error that names nothing useful | Called out in doc 04; verified as part of the Phase 2 gate |
| Retrying key generation destroys the previous key | Silent orphaning of an issued certificate | Guard inside the agent step, not only in the server's retry policy |
| Windows minidriver contends for the card | Intermittent, unreproducible APDU failures | Shared connections inside PC/SC transactions; never exclusive |
| Token can never be unblocked — no PUK | A blocked PIN costs every key on the token | Detected at inventory. `NotApplicable` on a Bio (accepted, console shows it as unrecoverable); `Disabled` elsewhere (refused by default, patch 0025) |
| Biometric verification path is exercised only on one device | The Bio flow is the least-travelled corner of the applet | Patch 0016 reads it, 0027 uses it; the temporary-PIN encoding is explicitly marked unverified in doc 03 |
| Touch-policy jobs reaped by the watchdog while waiting for a finger | Every enrolment on a touch profile fails | `AwaitingUser` is a distinct state with its own, longer deadline |

## What to do next

Ordered, each item small enough to finish in one sitting.

1. **0020 — `ICertificateAuthority`, `CaCapabilities`, the profile model.** Both
   backends registerable behind one interface, with the capability differences
   visible rather than discovered at issuance.
2. **0021 and 0028 — the built-in CA**, single and two-tier, with the `file` and
   SoftHSM key tiers. This is what makes an end-to-end demo possible with no
   directory at all.
3. **Stand up the lab** — four machines, described in [09](09-lab.md). The
   Phase 2 gate needs a domain to log into, and it is the only item here that
   needs infrastructure rather than time. Reach the cheaper rung first: PKINIT
   from Linux proves the certificate before a Windows client exists to blame.
4. **0022 and 0023 — profiles and on-card CSR signing**, the first point at
   which a key is generated on a token rather than read from one.

Items 1, 2 and 4 can start immediately. Item 3 is the long pole for the phase
gate and is worth starting in parallel.

Not on this list, deliberately: 0017 is blocked for want of a Linux reader,
0018 waits for 0023, and the temporary-PIN half of 0016 waits for 0027. All
three are recorded in *Patch progress* with their reasons.