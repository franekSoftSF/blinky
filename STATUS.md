# Project status — Blinky

**Last updated:** 2026-08-19
**Phase:** 0 — Design
**Overall:** phase 1 started - the PIV transport layer is real and driving hardware

The machine-readable version of this file is [status.json](status.json). Keep
both in sync; `status.json` is the one a build or dashboard should read.

## Where the project stands

The architecture is decided and documented end to end: process split, data
model, the PIV wire layer, both CA backends, the agent protocol, and the trust
boundaries. Nothing has been implemented yet.

The next milestone is deliberately unambitious: read a YubiKey correctly and
tell the truth about it, without writing a single byte to any card. Everything
after that depends on the PIV layer being right, and the PIV layer is the part
that cannot be reasoned into correctness — it has to be run against hardware.

## Validated on hardware

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

Full context in [docs/07-roadmap.md § Open questions](docs/07-roadmap.md#open-questions).

## Component progress

| Component | State | Notes |
|---|---|---|
| Architecture docs | **done** | Seven documents, all committed |
| Solution skeleton | **done** | `Blinky.slnx`, 11 projects, central package management, CI on windows-latest |
| Compose stack | **done** | postgres, api, worker, edge. `docker compose up -d` works |
| Edge and WAF | **done** | nginx + ModSecurity 3 + CRS v4, two listeners, mTLS forwarded to the API. 9 smoke checks green |
| `tools/PivProbe` | **done** | Read-only hardware spike; see *Validated on hardware* |
| `Blinky.Piv` | **transport, read path, attestation** | Patches 0010, 0011 and 0012. 108 tests. `tools/PivProbe` is now only printing, and verifies a live token against the pinned root |
| `Blinky.Contracts` | skeleton | Protocol version, `JobType`, `JobState`. Envelope in patch 0015 |
| `Blinky.Domain` | **done** | Patch 0013: eleven entities from doc 02, with the states the hardware turned up |
| `Blinky.Infrastructure` | **done** | Patch 0013: NHibernate mappings, generated schema, `SchemaValidator` reporting clean in both services |
| `Blinky.Api` | **enrolment done** | Patch 0014: bootstrap enrolment, agent CA, mTLS enforcement, heartbeat. Proven end to end by `tools/AgentEnrol` |
| `Blinky.Worker` | skeleton | Host and Serilog, no scanners. Job engine in patch 0026 |
| `Blinky.Pki` — built-in CA | not started | Phase 2, patches 0021 and 0028 (topology) |
| `Blinky.Pki` — ADCS | not started | Phase 3 |
| `Blinky.AdcsConnector` | skeleton | Windows service host. `ICertRequest3` in patch 0032 |
| `Blinky.Agent.Service` | **inventory done** | Patch 0015: enrols itself, watches readers, reports what it finds. Four tokens land in the database with correct firmware, form factor and slot states |
| `Blinky.Agent.Ui` | not started | Split out as patch 0018, immediately before the first workflow that needs a prompt |
| Angular console | not started | Phase 5 |
| Samba4 setup command | not started | Phase 6 |

## Phase progress

| Phase | Title | State |
|---|---|---|
| 0 | Design | **done** — docs, hardware spike, solution skeleton, CI, compose stack behind a WAF |
| 1 | See the token | **in progress** — 0010 to 0015 and 0019 done; 0016 and 0018 left |

| 2 | Issue something (built-in CA, on-card CSR, personalisation) | not started |
| 3 | ADCS (CMC, CES/CEP, DCOM connector) | not started |
| 4 | The boring lifecycle (renew, revoke, CRL, unblock) | not started |
| 5 | Console (Angular, RBAC, audit) | not started |
| 6 | Ship it (MSI, Samba4 setup, production compose) | not started |

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

1. ~~Create the GitHub repository~~ — done, `franekSoftSF/blinky`.
2. ~~Prove the PC/SC path on real hardware~~ — done, `tools/PivProbe`. Results
   in *Validated on hardware* above.
3. ~~Scaffold the solution~~ — done, patch 0002. Builds, 11 tests green, CI on
   windows-latest.
   ~~Stand up the stack behind a WAF~~ — done, patch 0003. 9 smoke checks green.
4. ~~Write `Blinky.Piv` against recorded transcripts~~ — done, patch 0010.
   Transport, chaining, error map, 46 tests, and the probe now runs on it.
5. **Run patch 0011 against three tokens**: factory, `ykman`-provisioned, and one
   with a blocked PIN. This is the go/no-go for the PC/SC-and-APDUs decision.
6. **Stand up the lab**: a Samba4 AD DC for the built-in CA path, and a Windows
   AD + ADCS pair for Phase 3. Both are needed eventually; the Samba4 one is
   needed first, because it is what makes the Phase 2 gate demonstrable.

Item 6 needs infrastructure; items 3 to 5 do not and can start immediately. The
token on the desk is factory-fresh in PIV, so it covers one of the three states
the Phase 1 gate needs; the `ykman`-provisioned and blocked-PIN tokens still
have to be prepared.
