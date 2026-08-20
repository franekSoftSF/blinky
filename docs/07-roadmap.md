# 07 — Roadmap

Numbered patches, each with a definition of done that can be checked by someone
who did not write it. A patch is not done because the code exists; it is done
when the DoD is demonstrable.

Both CA backends are built in parallel from Phase 2 onward — see
[04](04-pki-backends.md). Neither waits for the other.

## Phase 0 — Design

| # | Patch | DoD |
|---|---|---|
| 0000 | Read-only hardware spike, `tools/PivProbe` | Reads a YubiKey over PC/SC and reports firmware, serial, PIN/PUK/management-key state, slot occupancy and biometrics, writing nothing. Records the APDU transcript patch 0010 replays |
| 0001 | Architecture, data model, PIV layer, PKI backends, agent protocol, security | This document set. Reviewed, contradictions resolved |
| 0002 | Repository skeleton | `Blinky.slnx`, `Directory.Build.props`, `.editorconfig`, licence, CI that builds and runs unit tests |

| 0004 | The stack runs on a machine that is not localhost | Certificates carry the lab's hostnames, the agent validates the backend against a pinned CA rather than skipping the check, and `BLINKY_HOST` points the smoke test at another machine |
| 0003 | Compose stack and the edge: nginx + ModSecurity 3 + CRS v4, two listeners, dev certificates, smoke test | `docker compose up -d` then `./smoke-test.sh`: an attack on the console listener returns 403; the same attack on the agent listener is logged and passed; a PKCS#10 body reaches the API; a request with no client certificate is refused; a browser cannot forge `X-Client-Verify` |

## Phase 1 — See the token

Nothing is issued in this phase. The goal is a system that can look at a
YubiKey and tell the truth about it.

| # | Patch | DoD |
|---|---|---|
| 0010 | `Blinky.Piv`: PC/SC transport, transactions, command chaining, error map | Unit tests against recorded APDU transcripts; every SW in [03](03-piv-layer.md#error-map) mapped to a typed exception |
| 0011 | PIV read path: SELECT, GET VERSION, GET SERIAL, GET DATA per slot, GET METADATA | Against real hardware: correct serial, firmware, slot occupancy and PIN retry count for a factory token and for one provisioned by `ykman` |
| 0012 | Attestation: read `F9`, parse Yubico extensions, verify chain to the pinned root | A genuine token verifies; a self-signed forgery is rejected; a serial mismatch is rejected. All three are tests |
| 0013 | `Blinky.Domain` + `Blinky.Infrastructure`: entities, mappings, schema SQL, `SchemaValidator` | `docker compose up postgres` then service start logs a clean schema validation |
| 0014 | `Blinky.Api` skeleton + agent enrolment (mTLS, bootstrap token) | An agent installed from a dev build appears in the database with the correct `(hostname, domain)`; re-running the installer does not create a second row |
| 0015 | Agent service and the inventory job | A token inserted on a workstation appears in the database within one poll interval, with firmware, form factor and slot states correct |
| 0019 | Cards that are not YubiKeys are recognised, not ignored | A PIV card from another vendor is reported as unsupported with a reason, never mistaken for a broken YubiKey and never silently dropped; `6D00` is treated as absence throughout |
| 0018 | `Agent.Ui`, the session 0 split and the named pipe | A PIN prompt is drawn in the user's session and answered over a pipe the service accepts only from the interactive user (`INTERACTIVE`, not `Everyone`). Split out of 0015: inventory needs no prompt, and a window built three patches before the first one would be a shell nobody could test |
| 0016 | Bio Multi-protocol: detect slot `96`, read enrolment state and match attempts, confirm the temporary-PIN encoding | A Bio token reports `bio_state=Enrolled` with its attempt count; a non-Bio token reports `NotSupported` from the card's answer, not from its model name |
| 0017 | pcsc-lite interop, so the agent runs on Linux — **blocked**, no Linux machine with a reader on this bench; building it would mean shipping untested marshalling under everything else | The same `IApduTransport` over `libpcsclite`, with the register-width `DWORD` marshalling handled; the transcript replay tests pass on Linux and a reader test is run on one |

**Phase gate — met on 2026-08-20.** Factory, `ykman`-provisioned and
blocked-PIN tokens all read correctly, with no write from Blinky to any card.

The gate used to say "the console shows", which was unreachable by
construction: the console is Phase 5. It reads **the database** — that is what
the agent fills and what the console will later display.

| State | How it was produced | What the database said |
|---|---|---|
| Factory | untouched 5.4.3 and 5.7.1 | `Default`, 3/3 |
| Provisioned | `ykman` wrote an ECC P-256 key and certificate into 9A | slot `9A` **`Stale`** — Blinky did not put it there |
| Blocked PIN | three deliberate wrong attempts on the spare 5.4.3 | `Blocked`, 0 retries, **`puk_state=Default`** |
| Recovered | unblocked with the factory PUK | back to `Default`, 3/3 |

The blocked row is the one worth reading twice: blocked *and recoverable* is a
different operational situation from blocked with no PUK, and the two are
distinct states rather than one flag. The token was restored afterwards and is
back at its factory state.

## Phase 2 — Issue something

| # | Patch | DoD |
|---|---|---|
| 0020 | `ICertificateAuthority` + `CaCapabilities` + profile model | Both backends registerable; capability differences visible via API |
| 0021 | Built-in CA: generation script, issuing CA, `file` and `softhsm` key tiers | `scripts/new-ca.sh` produces a CA; the stack starts with an issuing CA under SoftHSM; `file` refuses to start without the explicit opt-in |
| 0022 | Certificate profiles incl. smart-card logon extensions and the SID extension | Issued certificate contains Client Auth + Smart Card Logon EKUs, UPN SAN and `1.3.6.1.4.1.311.25.2`, verified by `certutil -dump` |
| 0023 | Key generation, on-card CSR signing, attestation-gated submission | The PKCS#10 verifies against the attested public key; a CSR whose key does not match its attestation is rejected server-side |
| 0024 | Certificate write-back, `Issued`→`Installed`, Windows store refresh | Certificate appears in the user's personal store without unplugging the token |
| 0025 | Personalisation: management-key diversification, PUK escrow, PIN policy | A factory token ends the job with `mgmt_key_state=Diversified`, an escrowed PUK, and a user-set PIN. Issuance onto a token still holding the default key is refused with that reason. A Bio token personalises with `puk_state=NotApplicable` and no escrow step; a non-Bio token with a deleted PUK is refused unless `AllowUnrecoverableTokens` is set |
| 0026 | Job engine: leases, watchdog, `AwaitingUser`, per-step results | Killing the agent mid-job returns the job to `Pending` after the lease expires; a touch-policy job does not get reaped while waiting for a finger |
| 0027 | Biometric user verification during enrolment | Enrolment on a Bio token completes with a fingerprint and no PIN prompt; with match attempts exhausted the same job completes via PIN fallback; `Agent.Ui` shows the correct prompt in both cases |
| 0028 | Built-in CA topology: `single` or `two-tier`, chosen per CA instance | `scripts/new-ca.sh --topology single` and `--topology two-tier` both produce a chain that `openssl verify` accepts and that issues a usable smart-card logon certificate. `two-tier` sets `pathlen:0` on the root only. Publication puts the issuing CA in `NTAuthCertificates` and the anchor in the root container, correctly in both topologies. The health endpoint reports the nearer of the two CRL expiries. Changing the topology of an existing instance is refused with that reason |

**Phase gate:** `docker compose up -d`, plug in a factory YubiKey, enrol from the
console, and log into a Samba4 domain with it. No ADCS anywhere.

## Phase 3 — ADCS

| # | Patch | DoD |
|---|---|---|
| 0030 | `AdcsCertificateAuthority` + CMC request construction with an EA signature | A CMC produced by Blinky is accepted by a lab ADCS |
| 0031 | CES/CEP transport (MS-WSTEP / MS-XCEP) | Enrolment on behalf of a user through CES from the Linux container, with Kerberos auth |
| 0032 | `Blinky.AdcsConnector` (DCOM `ICertRequest3`) | Same enrolment through the connector; switching transports is one config value and no other change |
| 0033 | Backend registration checks | Registration fails with a named reason when the template supplies the subject in the request, when the EA certificate is missing or expired, or when the service account lacks Enroll |
| 0034 | Revocation through ADCS, CDP surfaced read-only | Revoking in Blinky revokes at the CA; the console links the CA's CDP and does not claim to own it |

**Phase gate:** the same enrolment workflow, same console, same audit trail,
against a Windows AD + ADCS lab — and against Samba4 + built-in CA — with only
the profile's CA instance differing.

## Phase 4 — The boring lifecycle

| # | Patch | DoD |
|---|---|---|
| 0040 | Expiry scanner and scheduled renewal | A credential 30 days from expiry produces exactly one renewal job, once, with `supersedes_id` set |
| 0041 | Revocation, CRL regeneration and publication | Revoking regenerates the CRL immediately; the CRL is reachable at the CDP URL in the issued certificate |
| 0042 | PIN unblock via escrowed PUK, with audit | An operator unblocks a blocked PIN; the disclosure event is recorded and exempt from retention. On a token with `puk_state=Disabled` or `NotApplicable` the action is absent from the console, not offered and then failed |
| 0043 | Lost / stolen / terminate / retire flows | Marking a token lost revokes every credential on it and does not attempt a wipe |
| 0044 | Stale-slot detection and reconciliation | A certificate replaced by `ykman` behind Blinky's back is detected and raised, not silently overwritten |
| 0045 | Retired-slot rotation for `9D` | Rotating an encryption key moves the old one to a retired slot; historic mail still decrypts |
| 0046 | Tray-resident agent UI, the inverted channel, and the certificate list | The tray lists what is on the token beside what the backend holds, and the two disagreeing is visible rather than hidden. The UI holds no PC/SC handle and caches no card state between openings. This is where the pipe stops carrying answers and starts carrying requests — spec in [10](10-agent-ui.md) |
| 0047 | PIN set and change from the workstation, with a complexity policy | The policy travels from the backend and is enforced in the **service**, never only in the window; the PIN never leaves the machine. A refusal for being too simple consumes no card attempt, and is worded differently from a mismatch and from `63CN` |
| 0048 | Unblock from the workstation: just-in-time PUK, used once, rotated after | The PUK reaches the service and never the UI or the disk; the disclosure is audited; the PUK is rotated immediately after use. On `puk_state` of `Disabled` or `NotApplicable` the action is **absent from the tray**, not offered and then failed |
| 0048a | Unblock over a telephone, for a workstation with no network | The agent shows a challenge, an operator answers it, and both sides derive the replacement PUK from the response and the challenge without exchanging it. A mistyped code is refused before it reaches the card, with the attempt counter untouched. An unblock that failed at the card is undone by a person saying so, because nothing else can know |
| 0049 | Renewal requested by the user | The new certificate is on the card and read back **before** the old credential is superseded and revoked; `supersedes_id` links them. The "slot already holds a key" guard is lifted by the job declaring itself a renewal, never in general |

## Phase 5 — Console

| # | Patch | DoD |
|---|---|---|
| 0050 | Angular shell, nginx `/api` proxy, auth | Same bundle runs in dev and compose with no rebuild |
| 0051 | Token and cardholder inventory, search, detail | Every state in [02](02-data-model.md) is visible and explained in the UI, including `Unknown` and `Stale` |
| 0052 | Enrolment, renewal, revocation, unblock from the console | Each action creates a job and streams its per-step progress |
| 0053 | RBAC: operator, auditor, administrator | An auditor cannot issue; a PUK disclosure requires the operator role; both are tested |
| 0054 | Audit browser | Every state change in a credential's life is reconstructable from the audit view alone |

## Phase 6 — Ship it

| # | Patch | DoD |
|---|---|---|
| 0060 | Agent MSI (WiX), upgrade path, identity persistence | `msiexec /i` over an older version keeps the agent GUID and configuration |
| 0061 | `blinky-samba-setup` | Publishes the CA into a fresh Samba4 provision, issues the KDC PKINIT certificate, prints what it changed |
| 0062 | Production compose profile | Real TLS, PKCS#11 tier, no default credentials, health checks, documented backup of the HSM and database |
| 0063 | Documentation pass and screenshots | A stranger can go from clone to smart-card logon using only the repository |

## Later

Named so they are not mistaken for oversights: OCSP responder, Windows
credential provider for logon-screen PIN reset (liftable from CredLoop),
SCP03/SCP11 secure channel, dual control for privileged profiles, hash-linked
audit chain, non-Yubico token support.

## Open questions

1. **Does the built-in CA need to be a separate container?** Currently it is a
   library inside `api` and `worker`. Splitting it would isolate the key
   material behind a process boundary at the cost of one more service. Revisit
   when the PKCS#11 tier is real.
2. **CES for enrol-on-behalf-of needs lab confirmation.** The RA-signed CMC path
   is documented to work; the exact authentication and delegation configuration
   on the CES side is the part to verify before 0031 is called done.
3. **How much does the agent do without the backend?** Currently: nothing that
   changes a card. Whether desk-side unblock should work offline with a
   pre-fetched, time-boxed PUK is a real question with a real security cost.
4. **Angular or nothing.** The console is the largest single piece of work in
   the plan. A CLI-first v1 would ship the engine sooner and is worth
   considering if Phase 2 runs long.
5. **Which HSM in production**, and does it need to hold the management-key
   master and the CA issuing key in the same partition? Needs site input before
   0062.
