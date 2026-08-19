# Project status — Blinky

**Last updated:** 2026-08-19
**Phase:** 0 — Design
**Overall:** design complete, no production code

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

The probe records an APDU transcript, which is the fixture the `Blinky.Piv`
unit tests replay in patch 0010. Transcripts contain the token serial and any
certificate on the card and are **not** committed — `out/` is ignored.

## Decisions locked

| Decision | Choice | Why |
|---|---|---|
| Runtime | .NET 10 | Same stack as the rest of these projects |
| Token access | PC/SC + raw PIV APDUs | No native library to deploy, no CLI output to parse, full access to the administrative commands a CMS needs. Validated on hardware before the decision was locked — see above |
| Token scope | YubiKey 5, PIV applet | Attestation and management-key policy are vendor-specific; other vendors are a later interface, not a v1 branch |
| CA backends | Built-in **and** ADCS, one interface, both from the start | Neither is optional: Samba4 has no ADCS, and a Windows estate will not accept a new CA |
| Built-in CA crypto | .NET for signing, BouncyCastle only for CMC/PKCS#7 | Less third-party crypto in the path that matters |
| CA key custody | PKCS#11 abstraction, three tiers: file, SoftHSM2, HSM | Compose default is real PKCS#11; production is a config change, not a rewrite |
| Management key | Per-token, HKDF-derived from an HSM-held master | One token's key opens one token; the database holds no key material |
| PIN | Never stored, anywhere, in any form | If a workflow appears to need a stored PIN, the workflow is wrong |
| PUK | Random per token, escrowed AES-256-GCM under an HSM KEK | Unblocking has to work over the phone; disclosure is audited and alertable |
| Transport | HTTPS REST + SignalR doorbell, no broker | One port, one certificate, one auth model; the doorbell carries no state |
| Agent shape | LocalSystem service + per-session UI process | Session 0 cannot draw a PIN prompt, and LocalSystem cannot prove who is at the keyboard |
| Identity | Agent = mTLS, user = Kerberos from the user's own session | No authorisation decision is made on the workstation |
| Store | PostgreSQL + NHibernate | Same as FAG, including the SQL schema script and `SchemaValidator` |
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
| `Blinky.Piv` | not started | Phase 1 — the risk lives here |
| `Blinky.Contracts` | not started | Envelope drafted in doc 05 |
| `Blinky.Domain` | not started | Entities and three state machines drafted in doc 02 |
| `Blinky.Infrastructure` | not started | Phase 1 |
| `Blinky.Api` | not started | Phase 1 (enrolment), Phase 2 (issuance) |
| `Blinky.Worker` | not started | Phase 2 (jobs), Phase 4 (lifecycle) |
| `Blinky.Pki` — built-in CA | not started | Phase 2 |
| `Blinky.Pki` — ADCS | not started | Phase 3 |
| `Blinky.AdcsConnector` | not started | Phase 3, only for estates without CES |
| `Blinky.Agent.Service` | not started | Phase 1 (inventory), Phase 2 (issuance) |
| `Blinky.Agent.Ui` | not started | Phase 1 |
| Angular console | not started | Phase 5 |
| Samba4 setup command | not started | Phase 6 |

## Phase progress

| Phase | Title | State |
|---|---|---|
| 0 | Design | in progress — docs done, solution skeleton pending |
| 1 | See the token (PIV read path, attestation, inventory) | not started |
| 2 | Issue something (built-in CA, on-card CSR, personalisation) | not started |
| 3 | ADCS (CMC, CES/CEP, DCOM connector) | not started |
| 4 | The boring lifecycle (renew, revoke, CRL, unblock) | not started |
| 5 | Console (Angular, RBAC, audit) | not started |
| 6 | Ship it (MSI, Samba4 setup, production compose) | not started |

## Risks being carried

| Risk | Impact | Current handling |
|---|---|---|
| PIV APDU layer misbehaves on real firmware in ways no emulator shows | Phase 1 redesign; everything downstream is blocked | Hardware test suite from patch 0011; `yubico-piv-tool` as an independent oracle |
| Management-key algorithm differs across firmware (3DES before 5.7, AES-192 after) | Personalisation fails on part of the fleet | Read `GET METADATA`, fall back once, record `Unknown` rather than guessing |
| ADCS template supplies the subject in the request, so no SID extension is emitted | Certificates issue cleanly and then fail to log anybody in | Backend registration refuses the combination up front (patch 0033) |
| CDP or AIA unreachable from domain controllers | Smart-card logon fails with an error that names nothing useful | Called out in doc 04; verified as part of the Phase 2 gate |
| Retrying key generation destroys the previous key | Silent orphaning of an issued certificate | Guard inside the agent step, not only in the server's retry policy |
| Windows minidriver contends for the card | Intermittent, unreproducible APDU failures | Shared connections inside PC/SC transactions; never exclusive |
| Touch-policy jobs reaped by the watchdog while waiting for a finger | Every enrolment on a touch profile fails | `AwaitingUser` is a distinct state with its own, longer deadline |

## What to do next

Ordered, each item small enough to finish in one sitting.

1. ~~Create the GitHub repository~~ — done, `franekSoftSF/blinky`.
2. ~~Prove the PC/SC path on real hardware~~ — done, `tools/PivProbe`. Results
   in *Validated on hardware* above.
3. **Scaffold the solution** — `Blinky.slnx`, the projects from the README, DI,
   configuration, Serilog, CI that builds and runs unit tests. Builds and does
   nothing, on purpose.
4. **Write `Blinky.Piv` against recorded transcripts** — transport, chaining,
   error map — with a real YubiKey used only to capture the transcripts.
5. **Run patch 0011 against three tokens**: factory, `ykman`-provisioned, and one
   with a blocked PIN. This is the go/no-go for the PC/SC-and-APDUs decision.
6. **Stand up the lab**: a Samba4 AD DC for the built-in CA path, and a Windows
   AD + ADCS pair for Phase 3. Both are needed eventually; the Samba4 one is
   needed first, because it is what makes the Phase 2 gate demonstrable.

Item 6 needs infrastructure; items 3 to 5 do not and can start immediately. The
token on the desk is factory-fresh in PIV, so it covers one of the three states
the Phase 1 gate needs; the `ykman`-provisioned and blocked-PIN tokens still
have to be prepared.
