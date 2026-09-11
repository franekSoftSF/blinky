# Project status — Blinky

**Last updated:** 2026-09-11
**Phase:** 2 — Issue something. **The gate is met**
**Overall:** on 24 August 2026 a person logged into the lab domain with a card
this system personalised and issued, against a Samba4 KDC, with no ADCS anywhere

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

Blinky now issues. On 20 August 2026 an operator created a job, an agent
claimed it, generated a key on a YubiKey 5.7.1, had the card sign its own
request, the server verified the attestation and issued, the agent wrote the
certificate back and read it back to check it — with the PIN typed by a person
into a window that the service cannot draw and never sees the contents of. The
run took thirteen seconds from claim to `Installed`, and `ykman piv info`
confirms the certificate independently.

The directory arrived. On 20–21 August 2026 the lab in [09](09-lab.md) was
built — a Samba4 domain controller for `BLINKY.LAB`, a host carrying the CA and
the CMS, a domain-joined Linux client and a domain-joined Windows client — and
with it the thing that had been refused all along became issuable.

On 21 August 2026 a `smartcard-logon` certificate was issued onto a YubiKey
5.4.3 from the Windows client: profile `smartcard-logon`, subject `CN=Admin`,
UPN `Admin@blinky.lab`, and a real `objectSid` read out of the directory rather
than typed. Thirteen seconds from claim to `Installed`. Yubico Authenticator —
which is not ours — shows the certificate in slot 9A with the serial number the
database recorded.

**And on 24 August 2026 somebody logged in with it.** `jnowak@blinky.lab`
signed into `BY-WIN-CLIENT01` with a YubiKey carrying a certificate from this
system's own two-tier CA, with the UPN and `objectSid` read out of the
directory, against the Samba4 KDC over PKINIT. No ADCS anywhere. That is the
Phase 2 gate, and it is met.

The card was fully personalised first, which is 0025: the management key derived
per token from a master and written nowhere, the PIN chosen by the holder, the
PUK replaced and escrowed. Both unblock paths were exercised on it — online
through the agent, and offline by reading a challenge to an operator and typing
the answer back.

Two findings from that day are worth carrying, because neither is a defect in
anything here. **Windows' inbox PIV minidriver would not produce a key
container** for a card meeting every requirement in SP 800-73 that could be
checked; Yubico's minidriver did, and is now a prerequisite for the workstation
— but it takes ownership of any card whose management key it does not
recognise, which is why 0025 writes the key behind the PIN and sets the flag
Yubico's tools read. And **a chain trusted for TLS is not thereby trusted for
logon**: the issuing CA must be in the workstation's NTAuth store, and Windows
reports its absence as `CERT_E_UNTRUSTEDCA`, which reads exactly like a broken
chain and sends everybody to look at the wrong thing.

Fourteen defects surfaced over that day, most of them this project's own; three
are named in [status.json](status.json).

Getting the first issuance run to work took six attempts, and every one of them
failed differently and for a real reason. All six are fixed, and each is listed under *What the run
found* below. The pattern is worth stating plainly: none of them were visible
without a domain, a Windows client and a person typing a PIN, which is the
argument for having built the lab rather than reasoning about it.

### What the run found

Six defects, in the order they surfaced. Each has a test.

| Symptom | What it actually was |
|---|---|
| Job failed at the PIN with `SCARD_W_RESET_CARD` | Windows shares the card with the smart card service, minidrivers and the logon screen, and any of them can reset it between two commands. A transaction stops interleaving, not resetting. Recovery — reconnect, select the applet, send again — was defined by the standard and not implemented |
| The PIN in the failure message, in the database | A failed transmit reported the whole command in hex. On a `VERIFY` those bytes are the PIN. It reached `jobs.result`, a column, a backup. Now redacted by instruction, header kept |
| Retry refused with `6982` on the last step | The recovery above, half-done: selecting the applet is exactly what clears the management key authentication, so the retried write reached a card that no longer knew us. Restored explicitly now — the management key only, never the PIN |
| `Issuance refused: 500` | The CA directory was `drwx------ root:root` and the API runs as uid 10001. It could not list it, and said "does not hold a CA" — which is a different sentence from "cannot read this" |
| The agent warned about a missing reader every minute | Windows starts the smart card service from a reader-arrival trigger, so a machine with nothing plugged in answers `SCARD_E_NO_SERVICE` forever. Said once now |
| The tray stopped refreshing, and would not reopen | `loading` was set without a `try/finally`, so one broken pipe silenced the window for good; and the window was closed rather than hidden, which WPF will not let you show again |

Two of these — the PIN in the log and the half-done recovery — were introduced
by this project rather than found in somebody else's. They are listed the same
way as the rest.

## Validated on hardware

Every rule that came out of a measurement, with its evidence and where it now
lives, is indexed in
[08 — What the hardware changed](08-hardware-notes.md). What follows is
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
| Where a passkey ceremony runs | In the agent, never in the browser | The provider dictates the rpId — `login.microsoft.com`, or the org's Okta domain — and a browser enforces rpId against the page origin. `navigator.credentials.create()` cannot be made to work from the console, whatever the console is served from |
| rpId and origin | Per-provider, per-tenant data carried in the job, never constants | They differ between providers and between Okta orgs, custom domains included. A hardcoded origin is a credential registered against the wrong relying party — which fails at sign-in, not at provisioning |
| Provisional FIDO2 PIN | Generated on the workstation, shown once, stored nowhere | Same rule as the PIV PIN, for the same reason. Where Okta delivers it by email instead, it never reaches Blinky at all |
| Passkey providers | Entra and Okta behind one interface; Google analysed and not built | Google exposes no API that accepts an attestation on behalf of a user, so the honest answer is a documented gap and a federation alternative, not a half-feature |
| Workstation app | Angular in a Tauri v2 shell, replacing the WPF tray | One UI technology for the whole product, and the same components as the console. WPF is a toolkit nothing else here uses and the console cannot share a line with |
| The seam between app and service | A loopback HTTPS API on the agent, not the named pipe | Chosen for shape: the product already speaks HTTP and JSON, and a local API leaves room for something other than this one application. The cost is an ACL the operating system was enforcing, rebuilt by hand in 0080 — recorded as a cost, not as a free choice |
| A new model's endpoints | Full CRUD when it describes configuration or people; create-and-transition when it records an event | A model in the database and nowhere in the UI is a model only its author can change. An audit trail that supports `DELETE` is not an audit trail |
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
| Do foreign tokens get a capability model — attestation yes/no, management key yes/no — and may a profile issue onto a token that cannot attest? | *Later* § non-Yubico tokens | measurement, then a decision |
| Does operator authentication by certificate stay the target, with password and TOTP as the way in — or does it become optional? | Phases 5 and 8 (0053a, 0086, 0023a) | a decision |
| Does the lab get an Entra tenant and an Okta org | Phase 7 (0076 onwards) | needs a decision and a subscription; contract tests need neither |
| Google prepare-only mode, or federation and nothing else | Phase 7 (§ Later) | product decision, not a technical one |

Full context in [07-roadmap.md § Open questions](07-roadmap.md#open-questions).

## Who owns what

Two agents work on this repository and the statuses are written so it is
obvious which of them a row is waiting on.

| Owner | Writes | Where |
|---|---|---|
| **Codex** | The console — the Angular application and everything a browser renders | `frontend/` |
| **Cloud.AI** | The backend, the agent, the PIV layer, the CA, the installer and the lab | `src/`, `scripts/`, `installer/` |
| **both** | A patch that needs one of each, and cannot be finished by either alone | |

A **both** row is the one worth watching: it is where work stalls without
anybody being blocked in their own half. 0052 is the live example — the page
cannot list profiles the API does not expose, and the API half will not be
written by whoever is writing the page.

## What each state means

| State | Meaning |
|---|---|
| **done** | Written, tested, and proved against hardware or a running stack |
| **done, unverified** | Written and unit-tested, but one specific claim has no evidence yet. The gap is named in *Implemented but not verified* below |
| **partly done** | Some of the definition of done is met and the rest is named in the row |
| **open** | Not started |
| **blocked** | Cannot be done here, with the reason |
| **deferred** | Deliberately postponed, with the patch it waits for |

Nothing is marked done because the code exists. It is done when the definition
of done in [07 — Roadmap](07-roadmap.md) can be checked by somebody who did not
write it.

## Patch progress

### Phase 0 — Design — **complete**

| # | Owner | Patch | State | Proof |
|---|---|---|---|---|
| 0000 | Cloud.AI | Read-only hardware spike, `tools/PivProbe` | **done** | Ran against five cards; findings in [08](08-hardware-notes.md) |
| 0001 | Cloud.AI | Architecture and design documents | **done** | Nine documents |
| 0002 | Cloud.AI | Solution skeleton, central packages, CI | **done** | CI green on windows-latest |
| 0003 | Cloud.AI | Compose stack and the edge (nginx + ModSecurity + CRS) | **done** | 13 smoke checks |
| 0004 | Cloud.AI | The stack runs on a machine that is not localhost | **done** | Certificates carry lab hostnames, the agent pins a CA, `BLINKY_HOST` points the checks elsewhere. Proved across the four-machine lab on 2026-08-24, which is what it was written for |

### Phase 1 — See the token — **gate met**

| # | Owner | Patch | State | Proof |
|---|---|---|---|---|
| 0010 | Cloud.AI | `Blinky.Piv`: transport, transactions, chaining, error map | **done, unverified** | Replay of a real capture plus hardware through the probe. `6Cxx` and outbound chaining have never run on a card |
| 0011 | Cloud.AI | PIV read path | **done** | Four tokens read correctly; `61xx` chaining exercised by a real certificate |
| 0012 | Cloud.AI | Attestation, verified to a pinned Yubico root | **done, unverified** | A genuine token verifies on hardware. Every rejection path is synthetic |
| 0013 | Cloud.AI | Domain, NHibernate mappings, generated schema, `SchemaValidator` | **done** | Clean validation in both containers; `jsonb` round trip against PostgreSQL |
| 0014 | Cloud.AI | Agent enrolment over mTLS, agent CA, heartbeat | **done** | Enrolled twice, one row, certificate used |
| 0015 | Cloud.AI | Agent service and the inventory job | **done** | Four tokens in the database within one poll |
| 0016 | Cloud.AI | Bio Multi-protocol | **done, unverified** | State reads correctly on a real Bio. The temporary-PIN encoding is unconfirmed — asking for one consumes a match attempt, and nothing needs it until 0027 |
| 0017 | Cloud.AI | pcsc-lite interop, so the agent runs on Linux | **blocked** | The reader is no longer what is missing: BY-LX-Client01 is joined, `pcscd` sees the reader, and both OpenSC and `libykcs11` enumerate the token. `install-linux-client.sh` now configures the sssd CA database, the smart-card switch and the PAM profile, and opens the reader to a remote session behind `--allow-remote-reader`. Card logon then stops **inside sssd** — `p11_child` finds the certificate and reports `No certificate found` without a message; trust, verification, the PKCS#11 module and privilege were each ruled out by test. Written up in [07 § Linux](07-roadmap.md). `kinit -X` is untried and is the next rung. The `IApduTransport` over `libpcsclite`, which is what this patch is actually for, is still unwritten |
| 0018 | Cloud.AI | `Agent.Ui`, the session 0 split and the named pipe | **done** | The pipe is driven from both ends in tests, and the window was run and typed into: a seven-character PIN accepted, range-checked and discarded. Two bugs found by running it that no test could have caught |
| 0019 | Cloud.AI | Cards that are not YubiKeys are recognised, not ignored | **done** | An HID Crescendo and a C4000 named and skipped, not dropped |

### Phase 2 — Issue something — **gate met**

| # | Owner | Patch | State | Proof |
|---|---|---|---|---|
| 0020 | Cloud.AI | `ICertificateAuthority`, `CaCapabilities`, profiles | **done** | Both topologies issue through one interface; capabilities describe the difference |
| 0021 | Cloud.AI | Built-in CA: generation script, key tiers | **done, unverified** | `scripts/new-ca.sh` builds both shapes and the chains verify. The SoftHSM key tier is not written — only `file`, and it refuses without an explicit opt-in |
| 0028 | Cloud.AI | Built-in CA topology: single or two-tier | **done** | Chain validates in both; `pathlen` asserted so the reversal cannot return |
| 0022 | Cloud.AI | Certificate profiles, smart-card logon extensions, SID extension | **partly done** | The profile model still lives in code, but is now shaped for the move: the certificate facts are slot-free `ProfileDescriptor` rows in `Profiles.All` and `ByName` builds from one of them, so a descriptor becomes a database row without anything above it changing. EKUs, UPN SAN and the SID extension are issued and asserted, and `smartcard-logon` refuses to issue without a resolved SID — proved by a 422 on the first live enrolment. On 2026-08-21 the profile issued for real against a directory: `CN=Admin`, UPN `Admin@blinky.lab`, SID read from `BLINKY.LAB`, certificate on the card and visible in Yubico Authenticator. A `client-auth` profile remains for use before a directory does. The profile model still lives in code rather than in the database, and is invisible to the console — see [11](11-console-enrolment.md) |
| 0023 | Cloud.AI | Key generation, on-card CSR signing, attestation-gated submission | **done** | Proved on two tokens: management key authenticated mutually (AES-192 and 3DES), key generated, attestation verified, card signed its own request |
| 0024 | Cloud.AI | Certificate write-back, `Issued`→`Installed`, store refresh | **done** | Written, read back, thumbprint compared, `Credential` in `Installed` and the slot in `Provisioned` — end to end through the job engine, twice. The Windows store half was answered on 2026-08-24 on BY-WIN-CLIENT01, and only with Yubico's minidriver: the inbox PIV minidriver produced no key container at all. On this bench machine ActivClient still owns the binding |
| 0025 | Cloud.AI | Personalisation: management key, PUK escrow, PIN policy | **done** | Token 29051525 went from factory to fully personalised on 2026-08-24 and was used to log into Windows for half an hour. `ykman piv info` reports no default management key and no default PIN, and prints "Management key is stored on the YubiKey, protected by PIN". Two gaps named rather than hidden: the master lives in `.env` rather than an HSM, so `/api/system/status` reports `productionReady: false`, and a card is personalised only at its first enrolment, so anything issued before this keeps its factory key |
| 0026 | Cloud.AI | Job engine: leases, watchdog, `AwaitingUser` | **done** | An operator creates a job, the agent claims it on a lease, runs it and reports; an expired lease is returned to the queue by the watchdog. `AwaitingUser` was watched live on 2026-08-21 — `Pending` → `Running` → `AwaitingUser` while a person typed a PIN, then `Succeeded` — which is what the row above was waiting for. The idempotency key is what stops a repeat, and a job that failed is only retried by naming a new `reason`: correct, and undiscoverable from the outside, since re-posting silently returns the dead job |
| 0027 | Cloud.AI | Biometric user verification during enrolment | **done** | A fingerprint replaces the PIN when the card can do it, with the PIN as fallback. Proved on a Bio 5.7.2: claim to certificate in five seconds, no PIN typed. The finding that made it work — `MatchOnce` is chosen at key generation, and a match will not satisfy a key generated with `Once` — is in [03](03-piv-layer.md) |
| 0018 | Cloud.AI | Agent UI: PIN and touch prompts across the session boundary | **done** | A PIN typed in the user's session reached the service over the named pipe and unlocked the card. The pipe is granted to `INTERACTIVE` and `LocalSystem` and to nothing else |
| 0023a | Cloud.AI | Enrol on behalf of, for the built-in CA | **open** | Marked *essential* in the roadmap. An operator asking for a certificate in somebody else's name is the normal case, and today the only thing between that request and a certificate asserting a stranger's identity is a shared token in a header. Needs a request signed by an identified enrolment agent, refused outright without one |
| 0029 | Cloud.AI | Reconcile credentials with what the sweep actually finds | **open** | A token reset outside Blinky leaves `Credential` rows reading `Installed` for certificates that no longer exist. The sweep corrects the *slot* and says nothing about the credential — found by resetting a token after two successful issuances |

### Phase 3 — ADCS — **open**

0030–0034, all Cloud.AI. None started; definitions of done in
[07 — Roadmap](07-roadmap.md). 0035 — writing to the directory — is deferred on
purpose, with the reason in the roadmap.

### Phase 4 — The boring lifecycle — **in progress**

The workstation half is finished ahead of the server half, because the agent was
in front of a person and the lifecycle jobs were not.

| # | Owner | Patch | State | Proof |
|---|---|---|---|---|
| 0046 | Cloud.AI | Tray-resident agent UI and the certificate list | **done** | The tray lists what is on the token beside what the backend holds, in Polish and English, light and dark. It holds no PC/SC handle and caches no card state between openings. Two defects found by running it that no test caught |
| 0047 | Cloud.AI | PIN set and change, with a complexity policy | **done** | The policy travels from the backend and is enforced in the **service**, never only in the window. A refusal for being too simple consumes no card attempt and is worded differently from a mismatch and from `63CN` |
| 0048 | Cloud.AI | Unblock from the workstation: just-in-time PUK | **done** | The PUK reaches the service and never the UI or the disk; the disclosure is audited and the PUK rotated immediately after use |
| 0048a | Cloud.AI | Unblock over a telephone | **done** | Verified on hardware over two cycles: challenge shown, operator answers, both sides derive the replacement PUK without exchanging it. A mistyped code is refused before it reaches the card, with the attempt counter untouched. Unreachable from the logon screen, which is what 0049a is for |
| 0041a | Cloud.AI | An OCSP responder, and the address that is already in the certificates | **open** | Half done, and it is the half that cannot wait: `CaPublication` carries `OcspUrls`, the CA emits authority information access when either list is non-empty, and `Blinky:Ca:OcspUrl` configures it. Unset everywhere, because nothing answers OCSP yet and a certificate advertising a responder that does not exist is worse than one advertising none. The address is there early because it is fixed at issuance — adding it later means re-issuing to everyone holding a card |
| 0040–0045a, 0049, 0049a | Cloud.AI | Expiry, renewal, revocation, retirement, `9D` rotation and escrow | **open** | Two have already been asked for by reality rather than by the plan: 0044, because an interrupted enrolment left a key in a slot that nothing below firmware 5.7 can clear, and 0041, because a credential issued to a card that never received it is waiting to be revoked |

### Phase 5 — Console — **in progress**

| # | Owner | Patch | State | Proof |
|---|---|---|---|---|
| 0050 | Codex | Angular shell, nginx proxy, auth | **done** | Built into an image and served by the edge on the same origin as the API — `/` to the console, `/api` to the API, deep links answered with `index.html`. Running in compose and on the CMS host |
| 0051 | Codex | Token and cardholder inventory | **partly done** | Tokens and their state are listed. The `MODEL` column shows the form factor because that is all the API sends, and cardholders have no endpoint at all |
| 0052 | Codex | Lifecycle actions from the console | **partly done** | **The API half is finished.** All five gaps in [11](11-console-enrolment.md) are closed: `GET /api/profiles` says what can be issued and what each profile demands of the person it is issued to; the cardholder catalogue and the directory lookup behind it landed on 2026-08-22; a failed job carries its `Result` into the overview; and `POST /api/jobs/enrol` takes a `cardholderId`, reads the identity from that row, sets `Job.CardholderId`, and refuses an unknown profile or an identity the profile cannot use at the post rather than a minute later on an agent. What is left is the page |
| 0053 | Codex | Who an operator is, and what they may do | **open** | Five patches. Everything today goes through one shared `X-Blinky-Operator` token: the audit trail cannot say *who*, nothing expires, and it leaks. It stays while the lab is being tested and goes when 0053e lands |
| 0053a | Cloud.AI | Operator authentication by certificate | **open** | mTLS on the console listener, against the user CA rather than the agent CA. The operator's identity arrives in its own header; `X-Client-Verify` stays blanked on 8443, because the smoke test checks a browser cannot forge an agent identity |
| 0053b | Cloud.AI | A session that can be ended | **done** | The rules are built and tested: revocation takes effect on the next request and is reported ahead of expiry, so an operator who ended a session sees that rather than a lapse. Two clocks bound it from different directions — an idle window activity moves, an absolute one nothing moves — because a console left open in a tab polls, and polling would otherwise make a credential immortal. The database holds SHA-256 of the token, never the token. Now wired into the middleware, so a session is resolved once per request and `IsOperator` accepts either it or the shared token — which stays until 0053e. **Proved on the deployment**: a session token reached `/api/profiles` with no shared token and got 200, sign-out returned 200, and the same token immediately afterwards got 401 |
| 0053c | Cloud.AI | Roles | **open** | operator, auditor, administrator — from directory groups where there is a directory, a local table where there is not |
| 0053d | Cloud.AI | The first super-admin, and the way back in | **open** | Bound by thumbprint, bootstrap closes after first use, and a break-glass that needs physical access to the server |
| 0053e | Cloud.AI | The shared token retired | **done, unverified** | The shared token is gone: `IsOperator` takes a session and nothing else, the header is out of the console store, the token boxes are off both settings pages, and `OPERATOR_TOKEN` is out of `.env.example`, the compose file and the installer. The service-credential half was never built and the reason is recorded — nothing automated ever used the token. **Not yet signed into from a browser**, which is why this is not deployed |
| 0054 | Codex | Audit browser | **open** | |

### Phase 6 — Ship it — **in progress**

| # | Owner | Patch | State | Proof |
|---|---|---|---|---|
| 0060 | Cloud.AI | Agent MSI and upgrade path | **done** | Installs a service, a tray and its configuration, and upgraded itself in place seven times in one evening. Built `x64`: an `x86` package puts the configuration in `WOW6432Node`, where the 64-bit agent does not look, and the install reports success while the service says it has no bootstrap token |
| 0061 | Cloud.AI | `blinky-samba-setup` | **done** | The chain is published into the Samba4 directory — root in Certification Authorities, issuing CA in `NTAuthCertificates` — and the KDC holds a PKINIT certificate. Both verified on BY-DC01 |
| 0062 | Cloud.AI | Production compose profile | **open** | Real TLS, the PKCS#11 tier, no default credentials, health checks, and a documented backup of the HSM and the database |
| 0063 | Cloud.AI | Documentation pass and screenshots | **open** | No pass and no screenshots yet. Three defects on the clone-to-logon path are fixed under this number, because they are what a stranger following the repository would have hit: `provision-dc.sh` orders `samba-ad-dc` after `network-online.target` and reloads it when it bound only to the loopback; `resign-issuing-ca.sh` is idempotent, having silently invalidated NTAuth, the workstation stores and the KDC chain three times in one day; `blinky-samba-setup.sh` rebuilds `kdc-chain.pem` around the certificate already on the controller when refreshed with `--from-url` alone |
| 0064 | Cloud.AI | The agent CA belongs to the deployment, and revocation is enforced at the edge | **open** | `dev-certs.sh` writes the agent CA unencrypted beside the certificates, which is right for a laptop and must never reach a customer. And nothing checks a CRL at the TLS layer: a withdrawn agent certificate still completes a handshake before the middleware turns it away |

### Phase 8 — The workstation app, and signing in — **open**

New, and written before any of it is built. The brief is
[14](14-workstation-app-and-sign-in.md); the definitions of done are in
[07 — Roadmap](07-roadmap.md). Numbered after Phase 7 and not thereby scheduled
after it.

The direction: enrolment stops being a window that appears on its own and
becomes something a person starts inside an application they opened and signed
into. The application is Angular in a Tauri v2 shell, built from the same
components as the console, so an operator who has used one has used the other.

Three things about it are worth reading before the table.

**It replaces finished code.** 0046, 0047, 0048 and 0048a are done and proved
on hardware. 0082 re-implements every screen in them and 0090 deletes the old
ones, at parity and not a patch earlier.

**It gives up an ACL the operating system was enforcing.** The seam becomes a
loopback HTTPS API on the agent. The pipe was granted to `INTERACTIVE` and
`LocalSystem`; a socket on `127.0.0.1` is open to every process of every user
on the machine. Keeping the pipe was possible — every call goes through a Tauri
command into Rust anyway, and Rust opens a pipe as easily as a socket — and was
rejected for shape rather than for capability. 0080 is the patch that rebuilds
the guarantee, and it is the riskiest thing in this phase.

**It reverses 0053a**, which said that a system for managing smart cards whose
operators sign in with smart cards is the only honest arrangement. The reason
is sound and 0053d half-stated it already: a smart card cannot be required to
sign into the system that issues smart cards before it has issued any. The
certificate path becomes the upgrade rather than the front door.

| # | Owner | Patch | State | Proof |
|---|---|---|---|---|
| 0080 | Cloud.AI | The agent's loopback API, and the ACL it has to replace | **open** | Four checks, each with its own test: the caller resolved to a PID and refused unless it runs as the interactive user of the console session; port and token readable only by that user and `SYSTEM`; any `Origin` header refused and no CORS emitted, so a web page cannot drive the agent; the certificate pinned rather than trusted |
| 0081 | Codex | `frontend/` becomes a library and two applications | **open** | Before 0082, not after: splitting a workspace once two applications exist means moving every file twice |
| 0082 | Codex | `Blinky.Workstation`: Angular in a Tauri v2 shell | **open** | HTTP in the Rust layer behind a Tauri command, never `fetch` from the WebView — a pinned certificate cannot be checked by the browser engine. The app reaches the backend only through the agent |
| 0083 | Cloud.AI | Signing in at the workstation: Kerberos, or a password | **open** | Kerberos is already the design in [05](05-agent-protocol.md). The password is new, for a machine with no domain: verified at the backend and never by the agent, per-user salt, rate-limited and lockable |
| 0084 | both | Enrolment the person started | **open** | No window appears that nobody asked for. 0049 folds in here |
| 0085 | both | The same ceremony, driven by an operator | **open** | Needs 0023a underneath it |
| 0086 | Cloud.AI | The panel's way in: bootstrap superadmin, password and TOTP | **done** | Endpoints under `/api/auth`, and a bootstrap administrator seeded at start only when there are no accounts at all. It arrives owing both a real password and a second factor, because a password an installer generated lives in a file, a shell history and a support bundle. Every step re-presents the password rather than exchanging it for a half-finished ticket, so there is one kind of token in this system instead of two. A password change ends every session founded on the old one. **Proved end to end on BY-CACMS on 11 September 2026**, including the defect only that run could find: the endpoint answered `totp-enrolment-required` before looking at the code, so a secret could be handed out and never confirmed |
| 0087 | Cloud.AI | TOTP, properly: enrolment, drift, recovery codes | **open** | A code accepted once inside its window and not again; a stated drift tolerance; recovery codes shown once and stored hashed |
| 0088 | Cloud.AI | FIDO2 as an operator second factor | **open** | The CTAP2 work of 0070–0076 turned on ourselves. After Phase 7, and not built twice |
| 0089 | both | Full CRUD for the models the panel manages | **open** | And a test for the exception: `AuditEvent`, `Job`, `Credential` and the disclosure rows record what happened and are not editable |
| 0090 | Cloud.AI | `Blinky.Agent.Ui` is removed | **open** | One commit, at parity |

### Phase 7 — FIDO2 — **open**

Nothing started. The brief is [12](12-passkey-provisioning-brief.md), the
definitions of done are in [07 — Roadmap](07-roadmap.md#phase-7--fido2-on-the-same-key).
0070–0072 stand alone and answer "is this returned key empty"; 0073 onwards
needs a tenant and an org that do not exist yet.

| # | Owner | Patch | State | Proof |
|---|---|---|---|---|
| 0070 | Cloud.AI | `Blinky.Fido`: CTAP2 over HID, `AuthenticatorInfo`, joined to the token by serial | **open** | Foundation for everything below. HID is not PC/SC: none of `Blinky.Piv` carries over |
| 0071 | both | The FIDO application in the inventory and on the token page | **open** | The API half is Cloud.AI's, the page is Codex's |
| 0072 | Cloud.AI | FIDO PIN set and change, FIDO reset | **open** | The half most likely to be wanted first, and it needs no identity provider |
| 0073 | Cloud.AI | `Blinky.Passkeys`: interface, normalisation, `Capabilities`, `EntraPasskeyDirectory` | **open** | Buildable today: fixtures and contract tests need neither hardware nor a tenant. The first thing to start |
| 0073a | Cloud.AI | `OktaPasskeyDirectory`, Factors route | **open** | Second implementation of the same interface |
| 0073b | Cloud.AI | Okta Preregistration API behind `OKTA__USEPREREGISTRATIONAPI` | **deferred** | Optional. May need an Early Access flag on the org; not default before it has run against a live one |
| 0074 | Cloud.AI | Contracts: `ProvisionFido2Credential` envelopes, protocol version bump | **open** | Breaking the protocol immobilises deployed agents; the bump is the point |
| 0075 | Cloud.AI | `PasskeyCredential`: entity, mapping, generated schema | **open** | Fourth state machine. No column may hold the provisional PIN |
| 0076 | Cloud.AI | The `makeCredential` ceremony in the agent | **open** | Hardware milestone. Verify on the bench against a mock relying party before any UI work |
| 0077 | Cloud.AI | Api orchestration, REST, drift, revocation | **open** | The challenge TTL becomes a job deadline; the agent never talks to a provider |
| 0077a | Cloud.AI | Okta wired into orchestration and the console | **open** | An agent change needed here is a design smell, to be reviewed rather than written |
| 0078 | Codex | The passkey panel | **open** | Waits on 0077, the way 0052 waits on the API today |
| 0079 | Cloud.AI | `13-passkey-provisioning.md` and the updates around it | **open** | Including the Google gap and the federation alternative, stated plainly |

Google Workspace is **not** on this list and is not an oversight: no public API
accepts a WebAuthn attestation on behalf of a user, so there is nothing to
implement. The analysis, the prepare-only concept and the federation
alternative are in brief §7 and in
[07 — Roadmap § Google Workspace](07-roadmap.md#google-workspace--analysed-not-scheduled).

## Implemented but not verified

The honest list. Each of these is written and unit-tested, and none has been
exercised against the thing it is really for.

| What | Why not yet | When it gets proved |
|---|---|---|
| YubiKey 5.8 | Newer than anything measured here. The version gates are open-ended, so it inherits the 5.7 path — but the pinned attestation root, the form-factor enum and the absence of card-side PIN complexity are assumptions until a card is read | `PivProbe`, which writes nothing |
| What a Crescendo V3 and a C4000 answer to the **standard** PIV instructions | Only the Yubico extensions have been measured on them, and those answer `6D00`. The rest is inferred from SP 800-73 | `tools/InsProbe`, extended from one instruction to the standard set |
| `6Cxx` retry-with-length | Comes from T=0 readers; every reader here negotiated T=1 | Needs a T=0 reader, or stays covered by hand-built cases |
| Attestation rejection paths | Forgeries, wrong roots and serial mismatches are synthetic — a real one would mean a counterfeit token | Stays synthetic; the genuine path is proved on hardware |
| The Linux transport | The client and its reader now exist; the `libpcsclite` marshalling is unwritten and card logon stops inside sssd | 0017 |
| Bio temporary PIN | Requesting one consumes a match attempt and needs a finger | 0027 |
| The SoftHSM key tier | Needs Pkcs11Interop and a container; the `file` tier proves the rest | The other half of 0021 |
| That a written certificate reaches the Windows certificate store | It does on BY-WIN-CLIENT01 — but only with Yubico's minidriver installed. The inbox PIV minidriver produced no key container, and on the bench machine HID ActivClient owns the binding | Done for the supported arrangement; the inbox-minidriver case stays unproved |
| Multi-machine deployment | Proved on 2026-08-24 across all four lab machines. Kept here until a second deployment repeats it | Done |
| Enrolment on a token whose slot already holds a key | The guard refuses rather than destroying it, which is right — but it also means a job that failed after generating cannot simply be retried into the same slot | 0029, with the reconciliation |
| ADCS, CES and the connector | No Windows AD lab yet | 0030–0034 |

## Component progress

| Component | State | Notes |
|---|---|---|
| Architecture docs | **done** | Nine documents |
| `Blinky.Piv` | **done** | Transport, read path, attestation. Drives the probe against real tokens |
| `Blinky.Contracts` | **done** | Protocol version, job enums, inventory contracts |
| `Blinky.Domain` | **done** | Eleven entities from doc 02 |
| `Blinky.Infrastructure` | **done** | Mappings, generated schema, `SchemaValidator` |
| `Blinky.Api` | **partial** | Enrolment, heartbeat, inventory. Issuance from 0023 |
| `Blinky.Worker` | **partial** | Hosts, logs and runs the job engine from 0026. CRL publication and the expiry scanner are 0040–0041 |
| `Blinky.Agent.Service` | **done** | Enrols into the machine certificate store, renews itself, watches readers, executes jobs, changes and unblocks PINs, and answers the tray. Installable as a service with `scripts/install-agent.ps1` |
| `Blinky.Agent.Ui` | **done** | Tray, certificate list, PIN change, unblock online and by telephone. Polish and English, light and dark |
| `Blinky.Pki` — built-in CA | **partial** | Issues, revokes, publishes a CRL, both topologies. SoftHSM tier outstanding |
| `Blinky.Pki` — ADCS | open | 0030–0033 |
| `Blinky.AdcsConnector` | skeleton | 0032 |
| Angular console | **partial** | Shell, inventory and recycle are up and served by the edge; enrolment waits on the API gaps in [11](11-console-enrolment.md) |
| `blinky-samba-setup` | **done** | Publishes the chain into the directory and issues the KDC's PKINIT certificate. Verified on BY-DC01 |
| `Blinky.Fido` | open | 0070. CTAP2 over HID — a second transport beside PC/SC, sharing nothing with it below the token |
| `Blinky.Passkeys` | open | 0073. One interface, Entra and Okta behind it, mirroring the shape of `Blinky.Pki` |
| `tools/PivProbe` | **done** | Read-only, drives `Blinky.Piv` against hardware |
| `tools/InsProbe` | **done** | Asks a card whether it knows an instruction, with a control |
| `tools/SchemaTool` | **done** | Generates the schema; `--roundtrip` proves it can be written to |
| `tools/AgentEnrol` | **done** | The whole enrolment flow; run twice by the smoke test |


## Risks being carried

| Risk | Impact | Current handling |
|---|---|---|
| PIV APDU layer misbehaves on real firmware in ways no emulator shows | Phase 1 redesign; everything downstream is blocked | Reduced by 0010: the probe runs on `Blinky.Piv` and produced byte-identical output on all three tokens. Hardware suite from 0011; `yubico-piv-tool` as an independent oracle |
| `6Cxx` and outbound chaining are untested on hardware | A T=0 reader, or the first certificate write, could fail in the field | Neither capture contains them: `6Cxx` needs a T=0 reader and outbound chaining needs a write. Hand-built cases cover both; the first real write lands in 0024 |
| The agent cannot run on Linux | Narrows deployment to Windows | Named, not hidden: `PcscContext.IsSupported`, an explicit exception, and patch 0017. The Linux client is now built and reads cards; what is missing is the transport and one unexplained refusal inside sssd |
| Management-key algorithm differs across firmware (3DES before 5.7, AES-192 after) | Personalisation fails on part of the fleet | Read `GET METADATA`, fall back once, record `Unknown` rather than guessing |
| ADCS template supplies the subject in the request, so no SID extension is emitted | Certificates issue cleanly and then fail to log anybody in | Backend registration refuses the combination up front (patch 0033) |
| CDP or AIA unreachable from domain controllers | Smart-card logon fails with an error that names nothing useful | Called out in doc 04; verified as part of the Phase 2 gate |
| Retrying key generation destroys the previous key | Silent orphaning of an issued certificate | Guard inside the agent step, not only in the server's retry policy. Observed working: a failed enrolment left a key in slot 9D and the retry was refused rather than overwriting it |
| An agent's own inventory sweep competes with its jobs for the reader | A job fails instantly with `SCARD_E_SHARING_VIOLATION` and no prompt, blaming nothing | Seen at a 5-second poll interval. Not yet fixed; the poll interval is the mitigation, [03 § One reader](03-piv-layer.md) |
| Windows minidriver contends for the card | Intermittent, unreproducible APDU failures | Shared connections inside PC/SC transactions; never exclusive |
| Token can never be unblocked — no PUK | A blocked PIN costs every key on the token | Detected at inventory. `NotApplicable` on a Bio (accepted, console shows it as unrecoverable); `Disabled` elsewhere (refused by default, patch 0025) |
| Biometric verification path is exercised only on one device | The Bio flow is the least-travelled corner of the applet | Patch 0016 reads it, 0027 uses it; the temporary-PIN encoding is explicitly marked unverified in doc 03 |
| Touch-policy jobs reaped by the watchdog while waiting for a finger | Every enrolment on a touch profile fails | `AwaitingUser` is a distinct state with its own, longer deadline |
| Microsoft Graph's `fido2Methods` endpoints are beta | The registration call changes shape and Phase 7 stops working against a live tenant | Isolated behind `IPasskeyDirectory`; recorded fixtures make the change visible as a failing contract test rather than as a broken deployment |
| A FIDO reset destroys every discoverable credential, and there is no PUK equivalent | An operator recycling a key wipes credentials nobody knew were on it | 0070 makes them visible before 0072 can destroy them, and the reset needs a confirmation that names the count |
| The challenge TTL bounds the whole ceremony | A person fumbling an unfamiliar PIN runs the job past the deadline and the credential is never registered | Options are fetched only after the key answers; expiry is a retryable code with a fresh challenge, and for Okta the pending factor is deleted first |
| The provisional PIN is shown once and stored nowhere | An operator who loses it before the key reaches its holder has no way to recover it | Deliberate, and the reason Okta's `ProviderDelivers` mode is worth having: the PIN goes to the user by email and never through a person |
| Phase 7 needs egress to somebody else's cloud | An on-premises product acquires an internet dependency at the point it is most sensitive | Only the `api` container; named in 0079's docs; every other container stays where it is |

## The bench, 2026-09-07

Two things arrived and neither has been run against anything yet.

**A YubiKey 5.8**, the first firmware here above 5.7. Nothing in the code
branches on the version where it matters — the gates are `>= 5.3` for
`GET METADATA` and `>= 5.7` for the AES-192 management key, and the algorithm
is read from the card rather than derived from the number — so 5.8 should walk
the 5.7 path. Three things are assumptions until a card is actually read.
[`YubicoRoots`](../src/Blinky.Piv/Attestation/YubicoRoots.cs) pins **one** root
with its SHA-256 checked at load, and issuance is gated on attestation, so an
intermediate chaining anywhere else stops 0023 rather than degrading it. The
form factor is a byte cast into an enum that stops at `0x07`, so a new shape
becomes a number in a column people read as a name. And if 5.8 enforces PIN
complexity of its own, the card will refuse for its reason and 0047 will explain
it in ours.

**An HID Crescendo SDK 2.1.0**, which turns out to answer a question and raise a
better one. It is a managed .NET library over PC/SC — it loads under .NET 10 and
its `SDK API` and `CLI Tool` folders are redistributable — with a full PIV
surface: key generation on the card, certificate read and write, signing, ACR
changes, PIN change, PUK reset, and a `NewToken` that personalises a card on its
own terms. It produces **no PIV attestation of any kind**; every `Attestation`
class in it belongs to FIDO. And Crescendo has no PIV management key at all —
access is governed by ACRs plus the PIN.

Four constraints from the [API reference](https://docs.hidglobal.com/hid-crescendo-sdk-v2.1/API%20references/html/index.html)
and the CLI's own help text, which shape anything built on this later:

- **The slot map is not PIV's, but the data objects are.** Key references are
  `0x9A` plus vendor slots `B0`, `B4` and `F0`, addressed alongside standard
  BER-TLV tags like `5FC105`.
- **Key generation offers RSA2048, RSA3072, RSA4096, CURVEP256 and CURVEP384**,
  and nothing else. No Ed25519, no X25519 — so a profile either picks an
  algorithm both a YubiKey and a Crescendo accept, or says which card it is for.
- **ACRs can be changed only on a Crescendo 4000 (applet V4), and only on a slot
  that is completely empty.** That inverts the order of operations: rules first,
  then the key. Today Blinky generates the key and the certificate follows.
- **`piv-pki-put` writes a private key, a certificate, or both.** A key can
  arrive on one of these cards from outside — which is exactly the situation
  attestation exists to detect, and the reason its absence is not a detail.

So supporting these cards is a **capability-model change, not a driver**. Blinky
will not ask a CA to sign without an attestation chaining to a pinned root, and
its personalisation *is* management-key diversification; neither has an
equivalent here. That is now an open question above rather than a line in
*Later*.

**And the SDK is not needed to talk to the card.** The split, from the code:

| | |
|---|---|
| **Standard SP 800-73** | `00A4` SELECT · `0020` VERIFY · `0024` CHANGE REFERENCE DATA · `002C` RESET RETRY COUNTER · `00CB` GET DATA · `00DB` PUT DATA · `0087` GENERAL AUTHENTICATE · `0047` GENERATE ASYMMETRIC KEY PAIR |
| **Yubico only** | `00FD` GET VERSION · `00F8` GET SERIAL · `00F7` GET METADATA · `00F9` ATTEST · `00FF` SET MANAGEMENT KEY · MOVE KEY |

The whole issuance path — generate, have the card sign its own request, write
the certificate back, PIN and unblock — is in the standard set, which
`Blinky.Piv` already speaks. What a foreign card cannot give is attestation, its
own serial and metadata, and mutual authentication against key `9B`. That is a
measurement waiting to be taken, not a conclusion: [`tools/InsProbe`](../tools/InsProbe/Program.cs)
exists for exactly this question and today asks it of one instruction. It probes
`0047` with a deliberately invalid algorithm identifier, so it writes nothing —
extending it to the standard set is small and answers this in an evening.

Where the SDK stays useful is as an **independent oracle** for what SP 800-73
does not describe — ACR coding, what `NewToken` really does, what
`PIVPutPKIData` looks like on the wire — the role `yubico-piv-tool` plays for
the YubiKey. And as a reference for the FIDO half of Phase 7, where there are no
APDUs at all because CTAP2 goes over HID.

## What to do next

**Signing in to the console is the one that matters.** Everything below it is
smaller. Today the console has no accounts: one `X-Blinky-Operator` token
stands for every operator, so the audit trail cannot say *who* revoked a
credential or disclosed a PUK, nothing expires, nothing can be withdrawn, and
the secret leaks the way shared secrets leak — shell history, a memory stick, a
chat window. The system that is supposed to prove who holds which credential
cannot say who is using it.

That is Phase 8's 0086 and 0087 together with three patches already written in
Phase 5, and they are one piece of work rather than five: **0086** a superadmin
with a password and TOTP, **0087** TOTP done properly with recovery codes,
**0053b** a session that can be ended, **0053c** roles so an auditor cannot
issue, and **0053e** named service credentials so the shared token can finally
be deleted rather than merely discouraged. 0053a — the certificate — is the
upgrade afterwards and is not in the way.

The rest, ordered, each small enough to finish in one sitting.

1. **Revoke the orphaned credential.** *(Cloud.AI.)* The attempt that failed at the last step
   left a `Credential` row reading `Issued` for a certificate that reached no
   card. One slot now has two credentials and one of them exists nowhere. This
   is 0029's problem arriving early, by a route 0029 does not cover: not a card
   reset behind Blinky's back, but Blinky's own job dying between issuing and
   writing.
2. **0029 — reconcile credentials with what a sweep finds.** *(Cloud.AI.)* A token reset
   outside Blinky leaves `Credential` rows reading `Installed` for certificates
   that no longer exist. The sweep corrects the slot and says nothing about the
   credential.
3. **A card can be personalised only by being issued to** *(Cloud.AI.)* — 0025 runs
   inside enrolment, so there is no way to take a card away from its factory
   defaults without also putting a credential on it, and every card issued
   before 0025 landed still holds its factory management key.
4. **0022's remaining half** *(Cloud.AI.)* — profiles in the database rather than in
   code. The console can see them now either way; what is left is that a new
   profile still means a rebuild.

**The enrolment page is the one to start first if two people are working.** It
was blocked on the API and is not any more: every endpoint doc 11 asks for
exists, and nothing on the console side of enrolment is built. That work is
Codex's, and the rest of this list is not.

Smaller, and each an hour: an interrupted enrolment leaves a key in a slot that
nothing below firmware 5.7 can clear, so recovery means `ykman piv reset` from
outside the product; the console's `MODEL` column shows the form factor because
that is all the API sends it; and the number on the MSI and the version the
console reports come from two different places, so telling whether a fix is
actually installed means reading a commit hash.

Not on this list, deliberately: 0017 is blocked one layer above anything this
project wrote — inside sssd, with the next step written down in
[07 § Linux](07-roadmap.md) — and the temporary-PIN half of 0016 waits for 0027.

### The agent, as it now stands

Everything below is on the workstation side and finished, so that the console
can be built against it rather than alongside it.

| | |
|---|---|
| Identity | The Windows certificate store — `certlm` as a service, `certmgr` when run by a person. Key non-exportable; verified by a refused export |
| Renewal | Every poll, replaced with a month to go, proving itself with the current certificate. No bootstrap token after the first start |
| Logging | `%ProgramData%\Blinky\logsgent-*.log`, daily, fourteen kept. Directory: SYSTEM, Administrators, and the account running |
| Deployment | `scripts/build-msi.sh` produces an MSI: service as LocalSystem, tray from `HKLM\...\Run`, configuration in `HKLM\SOFTWARE\Blinky\Agent` locked to SYSTEM and Administrators. `scripts/install-agent.ps1` does the same by hand |
| Reader | One operation at a time per process; a reader held by something else is reported with a reason rather than dropping the token from the list |
| Tray | Certificates with managed / not managed / unknown, PIN change, unblock online and by telephone |

Not done, and named rather than implied: **renewal of a cardholder's
certificate from the tray** (0049), **the touch prompt** — written, but no
profile sets a touch policy, so it has never been drawn — and the **service
having actually run in session 0**, which needs the installer to be run on a
machine.

### Specified, not built

The agent UI's second half is written down in [10](10-agent-ui.md) and numbered
0046–0049. All but the last are now built and on the tray: the certificate list,
PIN set and change with a policy enforced in the service, and unblock both
online and by telephone. **User-requested renewal (0049) is the one still
specified and not built**, and 0049a — the same recovery reachable from the
logon screen, where a user with a blocked PIN actually is — is not started
either.

Passkey provisioning is in the same condition, one step earlier: written down
in [12](12-passkey-provisioning-brief.md), numbered 0070–0079, and not started.
It is the first phase that reaches outside this network, and the first credential
Blinky would hand out that it did not itself create.

The reason it is a document before it is code: 0018's pipe carries *answers* —
the service asks, the person replies. All of this carries *requests*, and the
`INTERACTIVE` ACL stops guarding "who may answer a prompt" and starts guarding
"who may begin an operation on this token". Same ACL, more weight. Worth
deciding on purpose.

### Left in an odd state, on purpose

Token 29177301 still holds the certificate from the run of 20 August 2026,
because it could not be cleaned: `SCardConnect` on its reader returns
`0x8010000B`, the card held exclusively by something else. HID ActivClient is
the suspect — it runs on this machine, and the card became interesting to it at
exactly the moment a certificate landed in slot 9A. If that is confirmed it
sharpens what doc 08 records: ActivClient does not contend for an empty PIV
card, and does contend for one holding a credential.
