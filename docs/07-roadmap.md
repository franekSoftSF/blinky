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
| 0023a | Enrol on behalf of, for the built-in CA — **essential** | An operator asking for a certificate in somebody else's name is the normal case, not an exception. Today the only thing standing between that request and a certificate asserting a stranger's identity is a shared token in a header, and the record of who asked is a log line that the same token could have written. ADCS answers this and 0030 uses the answer: the request carries an **enrolment agent's signature**, so the CA enforces who was allowed to ask, and the evidence is cryptographic. The built-in CA has no equivalent and needs one — a request signed by an identified enrolment agent, refused outright when the signature is missing, from a certificate that says it may do this (`1.3.6.1.4.1.311.20.2.1`). **Buildable before 0053a and worth less until it lands**: the format, the signature check and the EKU rule can exist now, but an enrolment agent is a certificate, so naming *which operator* asked waits for operators to have them. The agent runs the ceremony on the cardholder's machine and never becomes the requester — it is carrying somebody else's request, which is the whole point |
| 0024 | Certificate write-back, `Issued`→`Installed`, Windows store refresh | Certificate appears in the user's personal store without unplugging the token |
| 0025 | Personalisation: management-key diversification, PUK escrow, PIN policy | A factory token ends the job with `mgmt_key_state=Diversified`, an escrowed PUK, and a user-set PIN. Issuance onto a token still holding the default key is refused with that reason. A Bio token personalises with `puk_state=NotApplicable` and no escrow step; a non-Bio token with a deleted PUK is refused unless `AllowUnrecoverableTokens` is set |
| 0025a | The management-key master and the PUK KEK behind PKCS#11, with SoftHSM2 as the first module | One interface with one cryptographic operation on it and no way to ask for a key; the keys separated per purpose and per generation; every key checked non-extractable against the token rather than assumed; use counted and logged with neither input nor output; the provider named on `/api/system/status`. Checkable by somebody who did not write it: with SoftHSM2 installed, `dotnet test --filter Pkcs11` is green rather than skipped; `SecretsTool list` prints both keys as sealed; a deployment that imports the extract of its existing master derives, through the token, the same management key the cards in the drawer are already holding. Nothing SoftHSM-specific in `src/` — the test for that is that adding a YubiHSM changes a module path and nothing else |
| 0025b | Master secrets status in the system console — codex | Sign in and open `/system`: a separate secrets card displays the provider, reported production readiness, every key generation and its exportability, configured write generations with missing keys called out, and per-process usage with restart semantics. A missing management-key master is neutral factory-key mode; unreadable generation-one PUK envelopes warn about `Blinky:Puk:Kek`. An older API without `secrets` has a neutral fallback. Check PL/EN and light/dark. Production build and rendered-panel tests pass; confirm against the deployed API using the signed-in console and its bearer authentication. |
| 0026 | Job engine: leases, watchdog, `AwaitingUser`, per-step results | Killing the agent mid-job returns the job to `Pending` after the lease expires; a touch-policy job does not get reaped while waiting for a finger |
| 0027 | Biometric user verification during enrolment | Enrolment on a Bio token completes with a fingerprint and no PIN prompt; with match attempts exhausted the same job completes via PIN fallback; `Agent.Ui` shows the correct prompt in both cases |
| 0028 | Built-in CA topology: `single` or `two-tier`, chosen per CA instance | `scripts/new-ca.sh --topology single` and `--topology two-tier` both produce a chain that `openssl verify` accepts and that issues a usable smart-card logon certificate. `two-tier` sets `pathlen:0` on the root only. Publication puts the issuing CA in `NTAuthCertificates` and the anchor in the root container, correctly in both topologies. The health endpoint reports the nearer of the two CRL expiries. Changing the topology of an existing instance is refused with that reason |

**Phase gate:** `docker compose up -d`, plug in a factory YubiKey, enrol from the
console, and log into a Samba4 domain with it. No ADCS anywhere.

## Phase 3 — ADCS

**An enrolment agent certificate is a prerequisite for this whole phase, not a
feature inside it.** Enrol-on-behalf-of against ADCS is refused without one, by
both routes — the DCOM connector of 0032 and CES/CEP of 0031 — because that
signature is how the CA enforces who was allowed to ask on somebody else's
behalf. There is no configuration that turns the requirement off.

`Blinky.Pki`'s built-in CA has no equivalent and never did; 0023a is where it
gets one. So the two are the same problem arriving from opposite directions:
0023a is a thing we choose to build because the evidence is worth having, and
0030 is a thing ADCS will not proceed without. Neither waits for the other, and
whoever does the first should write the request format so the second can use it.

The certificate itself has to come from somewhere, be valid, and carry
`1.3.6.1.4.1.311.20.2.1`. 0033 refuses registration with a named reason when it
is missing or expired, which is the earliest this can be discovered instead of
at the first enrolment.

| # | Patch | DoD |
|---|---|---|
| 0030 | `AdcsCertificateAuthority` + CMC request construction with an EA signature | A CMC produced by Blinky is accepted by a lab ADCS. Written: `IAdcsTransport`, `AdcsCertificateAuthority`, `CmcRequest` and `IEnrolmentAgentKeyStore` — the last of which is a sibling of `ICaKeyStore` rather than a third `KeyPurpose` behind `IKeyProvider`, because that interface computes an HMAC and a CMC needs a CMS signature. The encoding is asserted against RFC 5272; **the DoD is not met**, because it names a lab ADCS and there is none. **The CMC shape was wrong for a Microsoft CA**, found in MS-WCCE before any CA saw it, and fixed: a `RegInfo` control with `requestername` and a no-signature SignerInfo beside the agent's. **Met on 2026-09-13**: the lab CA issued a certificate from it for `AD\BlinkyUser`, with the subject, UPN and SID extension taken from that user's directory object. Not covered by this definition of done: the API now reads the cardholder's `DOMAIN\user` from the directory at issuance, and that read has not met a directory; the lab template refuses ECC card keys as too short |
| 0031 | CES/CEP transport (MS-WSTEP / MS-XCEP) | Enrolment on behalf of a user through CES from the Linux container, with Kerberos auth |
| 0032a | The connector dials the API | Nothing connects into the CA's network: the connector long-polls the agents' listener with a certificate from the agent CA, and the API accepts it on the connector routes by fingerprint only. Checked when a card is enrolled from the console through the real API and edge with `ADCS_TRANSPORT=ConnectorPolls`. Written and run against the lab CA with the probe playing the API - describe, registration check, issuance and revocation - and not yet through BY-CACMS |
| 0032 | `Blinky.AdcsConnector` (DCOM `ICertRequest3`) | Same enrolment through the connector; switching transports is one config value and no other change. Both halves are written and they talk to each other, and the enrolment agent's key lives on the connector's Windows server, where it can be non-exportable; the connector signs a `PKIData` the container built and refuses anything that is not one enrolment. On a machine with no CA, `tools/AdcsProbe --remote-agent` carries a CMC signed there into `ICertRequest3::Submit`. `Blinky:Ca:Backend=Adcs` points the API at it; CA instances and profiles are not yet read from the database, and no Microsoft CA has answered. The rest is listed in [15](15-adcs-connector.md) |
| 0033 | Backend registration checks | Registration fails with a named reason when the template supplies the subject in the request, when the EA certificate is missing or expired, or when the service account lacks Enroll. The checks are written - `GET /api/system/ca/checks`, `AdcsProbe --check` - with three outcomes, because counting only refusals passed a registration in which nothing had been verified. Run on HZCS01 as the service against the real smart-card template: every attribute check passed, and Enroll was found for the computer account once the check stopped judging `LocalSystem` by its local token. The revocation probe told a domain administrator from the computer. The template refused a P-256 key at submission for its minimum key size; the check now reads that minimum and, against the same template, warns that ECC keys will be denied. There is no registration flow for them to stop until CA instances are rows |
| 0034 | Revocation through ADCS, CDP surfaced read-only | Revoking in Blinky revokes at the CA; the console links the CA's CDP and does not claim to own it. Needs the integration account of [15](15-adcs-connector.md) to hold *Issue and Manage Certificates*, which is CA-wide unless certificate manager restrictions confine it - so that grant is designed before it is made. The lab CA revoked a test certificate through the connector and `AdcsCertificateAuthority.RevokeAsync`; nothing has been revoked from the console, and the CDP is not surfaced |
| 0035 | Writing to the directory: `userCertificate` and `altSecurityIdentities` — **someday, off by default** | A second, separate credential with write access to user objects, and the read path stays on the account that has none. That separation is the whole value of the read design: a read-only account is easy to ask a directory administrator for and easy to audit, and folding writes into it throws that away. Delegation narrowed to one organisational unit and those two attributes; an audit entry per write; disabled unless configured, so turning it off means the writes are impossible rather than merely not attempted. **Only strong mappings** — `X509IssuerSerialNumber`, `X509SKI`, `X509SHA1PublicKey`. The weak forms (`X509SubjectOnly`, `X509IssuerSubject`, `X509RFC822`) are exactly what KB5014754 disabled, and writing one would be this product undoing the protection it exists to enforce. **Not the route to a second identity on one card.** An administrative account signed into with an ordinary user's card sounds like a mapping and is not: the `smartcard-logon` profile embeds the holder's SID in `1.3.6.1.4.1.311.25.2`, which is the extension KB5014754 introduced precisely so that A's certificate cannot log on as B — a mapping on the administrative account does not sidestep that, it collides with it. Two certificates in two slots, each telling the truth about who it is, need no mapping and no delegation at all. This patch is for the certificate that *cannot* carry the right identity: one from a CA we do not control, a card honoured across a forest boundary, a migration from an existing PKI |

**Phase gate:** the same enrolment workflow, same console, same audit trail,
against a Windows AD + ADCS lab — and against Samba4 + built-in CA — with only
the profile's CA instance differing.

## Phase 4 — The boring lifecycle

| # | Patch | DoD |
|---|---|---|
| 0040 | Expiry scanner and scheduled renewal | A credential 30 days from expiry produces exactly one renewal job, once, with `supersedes_id` set |
| 0041 | Revocation, CRL regeneration and publication | Revoking regenerates the CRL immediately; the CRL is reachable at the CDP URL in the issued certificate |
| 0041a | An OCSP responder, and the address that is already in the certificates | A responder answers for the built-in CA, and a certificate issued after 0041 already names it - the address goes into authority information access at issuance and cannot be added to a card afterwards, which is why `Blinky:Ca:OcspUrl` exists before anything answers it. Turning it on is setting that URL and starting the container; it is not re-issuing anybody |
| 0042 | PIN unblock via escrowed PUK, with audit | An operator unblocks a blocked PIN; the disclosure event is recorded and exempt from retention. On a token with `puk_state=Disabled` or `NotApplicable` the action is absent from the console, not offered and then failed |
| 0043 | Lost / stolen / terminate / retire flows | Marking a token lost revokes every credential on it and does not attempt a wipe |
| 0044 | Stale-slot detection and reconciliation | A certificate replaced by `ykman` behind Blinky's back is detected and raised, not silently overwritten |
| 0045 | Retired-slot rotation for `9D` | Rotating an encryption key moves the old one to a retired slot; historic mail still decrypts |
| 0045a | Escrow for the `9D` key, because rotation alone cannot deliver 0045 | The encryption key is generated centrally, escrowed, and imported onto the card — the opposite of `9A` and `9C`, and correct for the opposite reason. A key that only ever existed on a card makes every message encrypted to it unreadable the moment the card is lost, and no amount of rotation brings it back. Attestation explicitly does not apply to this slot, and the exception is written down so nobody later "fixes" it. Needs a key import path in `Blinky.Piv`, which does not exist at all today. Where the escrowed keys live is [04](04-pki-backends.md): wrapped by a key an HSM holds, one key rather than one per person. **Phase 9 is the first thing that needs it**: mail on a phone is readable only with the card's own encryption key, so [16](16-smime-card-and-mobile.md) is built on this patch. Every decryption of an envelope is a disclosure event with a reason from a closed set |
| 0046 | Tray-resident agent UI, the inverted channel, and the certificate list | The tray lists what is on the token beside what the backend holds, and the two disagreeing is visible rather than hidden. The UI holds no PC/SC handle and caches no card state between openings. This is where the pipe stops carrying answers and starts carrying requests — spec in [10](10-agent-ui.md) |
| 0047 | PIN set and change from the workstation, with a complexity policy | The policy travels from the backend and is enforced in the **service**, never only in the window; the PIN never leaves the machine. A refusal for being too simple consumes no card attempt, and is worded differently from a mismatch and from `63CN` |
| 0048 | Unblock from the workstation: just-in-time PUK, used once, rotated after | The PUK reaches the service and never the UI or the disk; the disclosure is audited; the PUK is rotated immediately after use. On `puk_state` of `Disabled` or `NotApplicable` the action is **absent from the tray**, not offered and then failed |
| 0048a | Unblock over a telephone, for a workstation with no network | The agent shows a challenge, an operator answers it, and both sides derive the replacement PUK from the response and the challenge without exchanging it. A mistyped code is refused before it reaches the card, with the attempt counter untouched. An unblock that failed at the card is undone by a person saying so, because nothing else can know |
| 0049 | Renewal requested by the user | The new certificate is on the card and read back **before** the old credential is superseded and revoked; `supersedes_id` links them. The "slot already holds a key" guard is lifted by the job declaring itself a renewal, never in general |
| 0049a | A recovery tile on the logon screen | The challenge and response of 0048a are reachable **before** anybody logs in. Today they are not: the tray draws them, the tray lives in a logged-on session, and a user whose PIN is blocked cannot log on — so the one mechanism built for that situation is available only to people who do not need it. A credential provider that contributes one tile, authenticates nothing, unblocks the PIN and hands over to the standard smart-card tile. Deliberately **not** a credential provider replacement in the pGina shape: replacing the machine's provider means a bug locks everybody out, administrator included, and Windows' own smart-card logon is the thing we want left alone. A tile that crashes is dropped by LogonUI and the other tiles remain |

## Phase 5 — Console

| # | Patch | DoD |
|---|---|---|
| 0050 | Angular shell, nginx `/api` proxy, auth | Same bundle runs in dev and compose with no rebuild |
| 0051 | Token and cardholder inventory, search, detail | Every state in [02](02-data-model.md) is visible and explained in the UI, including `Unknown` and `Stale` |
| 0052 | Enrolment, renewal, revocation, unblock from the console | Each action creates a job and streams its per-step progress. Recycle landed; enrolment is blocked on the API rather than on the page - the console cannot see profiles, cannot see cardholders, and cannot see why a job failed. Spelled out in [11](11-console-enrolment.md) |
| 0053 | Who an operator is, and what they may do | Five patches. The shared `X-Blinky-Operator` token is one secret for everybody: the audit trail cannot say *who* revoked a credential, there are no roles, nothing expires, and it leaks — into shell history, onto a memory stick, into a chat window. It stays while the lab is being tested and goes when 0053e lands |
| 0053a | Operator authentication by certificate | mTLS on the console listener, against the CA that issues user certificates rather than the agent CA — two populations, two anchors. **The operator's identity arrives in its own header.** `X-Client-Verify` and `X-Client-Cert` stay blanked on 8443 exactly as they are today, because the smoke test checks that a browser cannot forge an agent identity and passing them through would undo it. A system for managing smart cards whose operators sign in with smart cards is the only honest arrangement |
| 0053b | A session that can be ended | A JWT cannot be revoked, which for an administrative console is the wrong trade: a server-side session gives "log out everywhere", an accurate answer to "who is signed in now", and a way to cut somebody off the moment their card reaches a revocation list. If a JWT, then fifteen minutes, refreshed against the certificate, with the CRL checked at each refresh — otherwise a revoked card keeps working until the token expires |
| 0053c | Roles | operator, auditor, administrator. From directory group membership where there is a directory — the LDAP client already reads it and needs nothing but read — and from a local table where there is not. An auditor cannot issue; a PUK disclosure needs the operator role; both are tested |
| 0053d | The first super-admin, and the way back in | Bound by the public key's thumbprint, not by a name: the same strong binding demanded of certificate mappings in 0035. Minted from Blinky's own PKI, or recorded by thumbprint when the certificate comes from an ADCS nobody here controls. The bootstrap path closes after first use. **And a break-glass that needs physical access to the server** — a command on the host that adds a thumbprint. Without one, a lost super-admin card locks everybody out of the console, which is the same blast radius that 0049a refuses for the logon screen |
| 0053e | The shared token retired | **Its premise was checked on 2026-09-11 and half of it was wrong.** Nothing automated authenticates with the shared token: `install-server.sh` only generates it, and the revocation-list publisher reads `/pki/`, which is public and needs no credential. So there is no caller to issue a named service credential *to*, and building the table before there is one would be inventing a user. What remains is the removal itself, and it is blocked on something real: the console signs in by pasting `X-Blinky-Operator` and has no sign-in page, so deleting the token today takes the console offline. Done when the console signs in with an account, the header is gone from `frontend/`, the nineteen `IsOperator` call sites accept only a session, and `OPERATOR_TOKEN` is out of `.env.example`, the compose file and the installer. If a non-human caller appears before then, it gets a named credential and this patch grows back the half it lost |
| 0054 | Audit browser | Every state change in a credential's life is reconstructable from the audit view alone |

## Phase 6 — Ship it

| # | Patch | DoD |
|---|---|---|
| 0060 | Agent MSI (WiX), upgrade path, identity persistence | `msiexec /i` over an older version keeps the agent GUID and configuration |
| 0061 | `blinky-samba-setup` | Publishes the CA into a fresh Samba4 provision, issues the KDC PKINIT certificate, prints what it changed |
| 0062 | Production compose profile | Real TLS, PKCS#11 tier, no default credentials, health checks, documented backup of the HSM and database |
| 0063 | Documentation pass and screenshots | A stranger can go from clone to smart-card logon using only the repository |
| 0064 | The agent CA belongs to the deployment, and revocation is enforced at the edge | `scripts/dev-certs.sh` writes the agent CA unencrypted next to the certificates, which is right for a laptop and must never reach a customer. `install-server.sh` mints it, or takes one that already exists. **And a revocation list for it**: an agent whose state is not `Enrolled` is already refused by [the middleware](../src/Blinky.Api/Security/AgentAuthenticationMiddleware.cs) — that is the defence and it works today — but nothing checks a CRL at the TLS layer, so a withdrawn certificate still completes a handshake before being turned away. `ssl_crl` on the agent listener, fed by the same publisher as everything else, closes that and makes the certificate worthless to anything else that trusts the same CA |
| 0098 | One mark for the whole product | The sidebar, the sign-in screen, the favicon, the API, the agent service and the tray icon all show the same key-in-an-arc mark, generated from `brand/*.svg` by `brand/build-assets.mjs`. Nothing in the repository still renders the hexagon-and-eye artwork, and the 16 px tray icon is the simplified mark rather than a downscale of the detailed one. Checkable by somebody else: `cd brand && npm install --no-save sharp@0.35.4 && node build-assets.mjs` leaves `git status` clean, and no stylesheet repaints the accent with `!important` |
| 0099 | One palette, generated into the console and the tray | `tools/PaletteTool` holds every colour as data; `frontend/src/tokens.scss` and both WPF theme dictionaries are written by it and by nothing else. No stylesheet and no component carries a hex - `PaletteTests` fails the build if one does, if a generated file was edited by hand, if the two themes stop defining the same roles, or if any pair of text colours drops below 4,5:1. The light theme covers the pages it never reached before, because the roles are redefined rather than the rules repeated |
| 0100 | The console's container image builds again | `docker compose build console` fails on `pnpm build` with `Cannot find module '/src/node_modules/@angular/cli/bin/ng.js'`, so the stack cannot be brought up from a clean checkout. Found while trying to look at the whole console for 0099; it failed the same way on `main` without any of that patch, so it was older than it. The cause was `frontend/.dockerignore` not existing: Docker reads only the ignore file beside the build context, and this context is `frontend/`, so `COPY . .` copied the developer's `node_modules` over the container's. Done when `docker compose up -d --build` serves the console again and `./smoke-test.sh` passes against it |
| 0106 | The service's prompt speaks the station's language | The prompt the service raises at sign-in - the one window not routed through `Strings` - says Cancel, Unlock and the PIN-length message in the station's language like the rest of the agent. The commit, 45eafff, says 0103 in its subject; that number was already the console's look, so this is 0106 and the subject is wrong rather than rewritten on origin. |
| 0107 | Passkey providers in the database, configured in the console | A `PasskeyProvider` row per Entra tenant or Okta org, with full CRUD under Administration, administrators only; nothing about providers in `.env` or compose. The credential is generated by Blinky by default and only its public half is shown - a certificate for Entra, a JWK with an RFC 7638 kid for Okta - or imported and sealed on arrival; either way it is AES-GCM under a key derived from the PUK KEK and bound to the row and the kind, and no response, audit event or log carries it. Name and kind are fixed once created; a provider with registered passkeys is disabled, not deleted. A test button asks the provider something harmless and reports its answer. Done when a provider made in the console registers a passkey, which waits on a tenant or an org |
| 0103 | One family: the console drawn as BlinkyLite's is | BlinkyLite's web console copied this one's layout and then got its own, flatter look; this brings it back. The neutrals of both themes are BlinkyLite's, value for value, generated from `Palette.cs` as before, with only the accent Blinky's - one cyan fill in both themes carrying near-black text, as BlinkyLite's green does. Segoe UI at 15px, radii 8/12/14, no gradient, glow, blur or upper-case labels. The shell takes BlinkyLite's measures: a 250px sidebar with the active item marked by a bar, a status dot filled or hollow, the operator on the left of the top bar and language, theme, refresh and sign-out on the right. Sign-in is a card in the middle of the page with the mark at 64px and a language select. States are a word with a marker, by shape as well as colour. Done when both consoles side by side read as one product in both themes, `PaletteTests` pass, and the console builds and its tests pass |
| 0101 | The console's session leaves JavaScript | The session is a cookie - `blinky_session`, `HttpOnly`, `Secure`, `SameSite=Strict` - and no code path reads it back: nothing in `frontend/` touches `sessionStorage`, and the API reads no `Authorization` or `X-Blinky-Session` header. Every state-changing operator request carries `X-Blinky-Csrf` matching the readable `blinky_csrf` cookie, refused with 403 when it does not, exempting only the three sign-in routes. Proved by signing in against a running stack: the response sets both cookies with those flags and no token in its body, the console works across a refresh, `document.cookie` does not contain the session, a POST with the header stripped is refused, and signing out removes both cookies |
| 0102 | An enrolment token is a row, not a constant | No enrolment secret is left in `docker-compose.yml` or `.env.example`, and a test fails the build if one comes back. A token is made from the console with a term, a number of machines and a purpose; its value is shown once; every use is counted on the row; revoking it takes effect on the next request. An ADCS connector enrols the same way with a token whose purpose is `AdcsConnector`, and the API records the fingerprint itself - `ADCS_CONNECTOR_CLIENT_FINGERPRINTS` is gone. Proved against a running stack: a one-use token enrols one agent and is refused the second time, an agent token presented as a connector is refused, a revoked token is refused, the connector's registration lands in `connector_registrations`, and the console makes, lists and revokes |
| 0104 | One connector reads the CA and the directory | With `DIRECTORY_VIA=Connector` the API holds no credential for the domain: search, find, members, write access, NetBIOS name and the probe are answered by the ADCS connector as its own service account, with the same `LdapDirectory` filters a direct bind uses. Done when, on a member running the connector as a domain account, the console's directory test reports the DC and naming context it read, a person is found from the console, and one card is enrolled through ADCS with its `DOMAIN\user` read this way |
| 0105 | The connector installs and enrols itself, from the console's downloads | An operator downloads the connector MSI and its install script from the console, checks them against the listed SHA-256, makes a connector token, and runs one script on the CA's neighbour; the connector enrols itself and polls. Done when that happens on a member server with nothing copied by hand, the console lists the connector, and an enrolment goes through it |

## Phase 7 — FIDO2 on the same key

The brief is [12 — Passkey provisioning](12-passkey-provisioning-brief.md);
what it turns into is below. Two things make this phase unlike the six before it.

**The transport is new.** PIV speaks APDUs over PC/SC, CTAP2 speaks its own
protocol over HID. The agent, the job engine, the inventory model and the
console all carry over; nothing underneath them does. That is why 0070 is a
foundation patch rather than the first feature.

**Blinky does not mint this credential.** A WebAuthn credential is created by
the authenticator in a ceremony with the relying party — there is no way to
generate one server-side and write it into a slot the way a certificate is
written. All Blinky can do is run the ceremony on somebody's behalf and hand
the result to a provider that accepts it, which makes the phase per-provider by
construction: Entra proves nothing about Okta, and both prove nothing about
Google, which today accepts no such handover at all (§ Later).

**There is a working reference.** KeyEnroll (`github.com/inowakowski/KeyEnroll`,
MIT) does on-behalf enrolment from a desktop for Entra, Okta and PingOne, on
`python-fido2`. 0073/0073a port its provider half; its enrolment engine is the
reference for 0072 and 0076, and its software CTAP 2.1 authenticator is the
model for testing the ceremony without a key. It has run on hardware for Okta
only — the rest of it is evidence of shape, not of behaviour.

0070–0072 need no identity provider at all and are worth having on their own:
they answer *is this returned key actually empty*, which a CMS that manages
only PIV answers wrongly.

| # | Patch | DoD |
|---|---|---|
| 0070 | `Blinky.Fido`: CTAP2 over HID, `AuthenticatorInfo`, correlated to the PIV token by serial | A plugged key reports AAGUID, CTAP versions, whether a PIN is set, PIN retries, and discoverable-credential slots used and free — joined to the same token the PC/SC sweep already sees, by serial. A key with the FIDO application disabled says so; it is not a failure. Denied HID access is an environment error naming elevation, because the tray does not run as LocalSystem and the service does. Nothing is written to any key |
| 0071 | The FIDO application in the inventory and on the token page | The console shows PIV and FIDO beside each other, with **two** PIN retry counters that are never collapsed into one, and lists the relying parties a key holds discoverable credentials for. "Is this returned key empty" is answerable from the console without `ykman` |
| 0072 | Control it: FIDO PIN set and change, and FIDO reset | The policy is enforced in the service and not only in the window, as in 0047. Reset is refused without a confirmation that names how many discoverable credentials it destroys, and reports the vendor's power-cycle window honestly when it has passed. A test on hardware asserts the thing an operator will otherwise assume wrongly: `ykman piv reset` leaves FIDO untouched, and a FIDO reset leaves PIV untouched |
| 0073 | `Blinky.Passkeys`: `IPasskeyDirectory`, the normalised `PasskeyCreationOptions`, `Capabilities`, and `EntraPasskeyDirectory` | Recorded Graph fixtures normalise into one model; contract tests pass with no tenant and no hardware. rpId and origin come from the provider's answer and never from a constant — asserted by a test that fails on a `login.microsoft.com` literal anywhere outside `EntraPasskeyDirectory`. `Capabilities` carries `SupportsRegistration` and `PrepareOnly` from the first commit, so the Google question can be answered later without reshaping the interface |
| 0073a | `OktaPasskeyDirectory`, the Factors route | The same interface against Okta's naming (`attestation`/`clientData` rather than `attestationObject`/`clientDataJSON`), with origin taken from the org's domain — including a custom one — preferring what the API returns over what is configured. A ceremony failed on purpose leaves no factor behind: the `PENDING_ACTIVATION` factor is deleted in cleanup, proved by a test that fails the ceremony deliberately |
| 0073b | Okta's Preregistration API, behind `OKTA__USEPREREGISTRATIONAPI` — optional | The provisional PIN is delivered by Okta's own email template and never appears in Blinky's UI or database. Off by default, behind the same interface, and not made default before it has run against a live org — the API may need an Early Access flag and is shaped for Yubico's fulfilment programme rather than for ours |
| 0074 | `Blinky.Contracts`: the `ProvisionFido2Credential` envelopes and a protocol version bump | Four messages — prepare, ready, ceremony, result — carrying no provider semantics beyond an opaque tag for the audit trail. A repeated ceremony request with the same challenge is the same operation, not a second one. The version is bumped, and an agent from before the bump refuses cleanly rather than misreading a field |
| 0075 | `PasskeyCredential`: entity, mapping, generated schema | `Requested → KeyReady → ChallengeIssued → Provisioned → Registered → Revoked`, plus `Failed` with a reason, following the three state machines that exist. Schema generated by `tools/SchemaTool`, `SchemaValidator` clean at both services' start. **No column can hold the provisional PIN** — enforced by the mapping rather than left as a convention the next patch can forget |
| 0076 | The ceremony in the agent — *hardware milestone* | `clientDataJSON` built byte-exact with the challenge as received, `clientDataHash` its SHA-256, and `attestationObject` passed through as produced rather than re-encoded. Touch and PIN prompts drawn by `Agent.Ui`, labelled as the **FIDO2 PIN** and distinguishable from the PIV PIN by a person who does not know there are two. `forceChangePin` and `SetMinPinLength` are used where `AuthenticatorInfo` says CTAP 2.1 exists and never assumed; where it does not, the fallback is an operator-set PIN and the UI says so. Proved on the bench against a mock relying party, before any provider is in the loop |
| 0077 | Api orchestration, REST, drift and revocation | Options are fetched only after `Fido2Ready` and dispatched immediately, with the challenge TTL enforced as a job deadline; expiry fails with a retryable code rather than a dead job. The passkey list merges the database with the provider's live list and shows disagreement instead of hiding it. Revoke deletes at the provider **and then** marks locally, never the other way round. The agent never speaks to Entra or Okta — every provider call is server-side |
| 0077a | Okta wired into the orchestration and the console | The same job completes against an Okta org **with no change in `Blinky.Agent.Service`**. A change that turns out to be needed there is reviewed as a design smell before it is written: the ceremony is meant to be identical, and if it is not, the abstraction is in the wrong place |
| 0078 | The passkey panel *(Codex)* | Provider selector showing configured providers, and rendering an analysis-only provider visible-but-disabled with the reason rather than omitting it. Live ceremony status — waiting for the key, touch, PIN, registering. The panel says *whether* a provisional PIN was set and that it was shown on the workstation; it never displays one, because since 0074 no message from the agent carries it — this DoD used to require the console to display it once, which would have put a PIN through the API. Drift badge where the provider and the database disagree |
| 0079 | Docs: `13-passkey-provisioning.md` and the updates around it | Tenant prerequisites for both providers, the egress the `api` container needs and the fact that nothing else in the stack gains any, the chain-of-custody note for a key that ships as a live credential, and the Google gap stated plainly next to the federation alternative. Updates to [05](05-agent-protocol.md), [06](06-security.md), `README.md` and both status files |

**Phase gate:** an operator provisions a fresh YubiKey from the console for an
Entra lab-tenant user and for an Okta lab-org user; each of them signs in at
their own provider with that key; the provisional PIN must be changed on first
use; revoking from the console removes the method at the provider; every step
is in the audit trail; and the unit and contract tests are green with no
hardware, no tenant and no org.

**What this phase adds that no earlier one has: a dependency on somebody else's
cloud.** Everything through Phase 6 runs on-premises. Here the `api` container —
and only that container — needs to reach `graph.microsoft.com`,
`login.microsoftonline.com` and the Okta org URL, and the lab in
[09](09-lab.md) needs a tenant and an org that no script in this repository can
provision. Worth deciding on purpose rather than discovering at deployment.

## Phase 8 — The workstation app, and signing in

The brief is [14 — The workstation app, and signing in](14-workstation-app-and-sign-in.md).
Numbered after Phase 7 and not thereby scheduled after it; the phases have
never run in order, and 0046–0048a of Phase 4 landed before Phase 3 started.

Three things make this phase unlike the others, and all three are arguments in
[14](14-workstation-app-and-sign-in.md) rather than assumptions here.

It **replaces working code**: `Blinky.Agent.Ui` is finished and proved on
hardware, and 0082 re-implements every screen in it. It is removed by 0090 and
not a patch earlier.

It **gives up an ACL the operating system was enforcing**. The named pipe was
granted to `INTERACTIVE` and `LocalSystem`; a loopback socket is open to every
process of every user on the machine. 0080 exists to rebuild that guarantee and
is the riskiest patch here by a wide margin — a local agent API is a shape with
a long history of advisories behind it, nearly all of them one of the four
checks in its definition of done.

And it **reverses a decision**: 0053a says operators sign in with smart cards,
and 0084 gives them a password and a TOTP code.

| # | Patch | DoD |
|---|---|---|
| 0080 | The agent's loopback API, and the ACL it has to replace | The service serves HTTPS on an ephemeral loopback port with a certificate generated at install. **The pipe's guarantee is rebuilt in four checkable pieces, each with its own test**: the connecting process is resolved to a PID and refused unless it runs as the interactive user of the console session; the port and a per-session token are readable only by that user and `SYSTEM`; a request carrying **any** `Origin` header is refused and no CORS header is ever emitted, so a web page cannot drive the agent; and the certificate is pinned by the client rather than placed in a Windows trust store. A second signed-in user cannot reach it, and neither can a browser |
| 0081 | `frontend/` becomes a library and two applications | The console builds and runs exactly as it does today, from `projects/console`, with its shared components in `projects/ui` and nothing about the served bundle changed. Done **before** 0082: splitting a workspace after two applications exist means moving every file twice |
| 0082 | `Blinky.Workstation`: Angular in a Tauri v2 shell | The certificate list of 0046 is drawn by the new app against an otherwise **unchanged** `Blinky.Agent.Service`, using the components the console uses. No APDU is issued from the app and it holds no PC/SC handle — asserted, not intended. HTTP happens in the Rust layer behind a Tauri command, never as `fetch` from the WebView, because a pinned certificate cannot be checked by the browser engine. The app reaches the backend only through the agent. Bundled as MSI and NSIS, and a workstation needs no .NET for the UI |
| 0083 | Signing in at the workstation: Kerberos, or a password | Both produce a user identity the **backend** verifies, never the agent. A domain machine signs in with a SPNEGO ticket from the interactive session and no password is typed; a machine with no domain signs in with a password that is checked at the backend, hashed with a per-user salt, rate-limited and lockable per account. A password never reaches the agent's log, the local API's log or the database in the clear |
| 0084 | Enrolment the person started | A user opens the app, signs in, asks for a credential, and the job is created for them. **No window appears that nobody asked for** — the ceremony is reachable only from an application already in front of somebody, and it waits as long as the person needs. 0049's user-requested renewal folds in here |
| 0085 | The same ceremony, driven by an operator | An operator enrols on somebody else's behalf from the console: the request is theirs, the card is at the cardholder's workstation, the app there runs the ceremony, and the agent never becomes the requester. Needs 0023a's signed request underneath it, and inherits whatever 0086 decides about who an operator is |
| 0086 | The admin panel's own way in: a bootstrap superadmin, password and TOTP | One superadmin created at deployment, with **TOTP required from the first sign-in** rather than added later. The certificate path of 0053a is not cancelled by this; it becomes the upgrade, and a role may require it. The bootstrap closes after first use, as 0053d already demands |
| 0087 | TOTP, properly: enrolment, drift, recovery codes | A code is accepted once and not again inside its window; clock drift is tolerated by a stated number of steps and no more; recovery codes are shown **once** and stored hashed. Without these the first lost telephone is a break-glass event |
| 0088 | FIDO2 as an operator's second factor — **after Phase 7** | The same CTAP2 work 0070–0076 needs, turned on ourselves: an operator registers a passkey against this console. Deliberately not built twice, and deliberately not before the ceremony exists |
| 0089 | Full CRUD for the models the panel manages | Every entity that describes configuration or people is listable, readable, creatable, editable and deletable from the panel. Every entity that records something that happened — `AuditEvent`, `Job`, `Credential`, PUK disclosures — is not, and a test asserts the second list rather than trusting the reviewer of the next patch to remember it |
| 0090 | `Blinky.Agent.Ui` is removed | Deleted in one commit, once 0082 and 0084 do everything 0046 through 0048a do. Not before: two clients on one local API means two places to fix the same defect |

**Phase gate:** a user on a domain workstation and a user on a machine with no
domain each open the app, sign in their own way, and enrol a card they asked
for; an operator enrols on behalf of a third person through the same ceremony;
and an administrator signs into the panel with a password and a TOTP code,
having been forced to set the second factor before anything else.

## Phase 9 — S/MIME on the card and on the phone

The design is [16 — S/MIME on the card, and the same mailbox on a phone](16-smime-card-and-mobile.md).
Nothing here is built, and the block is not the tenant — a Workspace ONE UEM
SaaS tenant exists. **The block is that Blinky cannot sign or decrypt anything
yet**: two profiles, both on `9A`, no key import, no mail address on a
cardholder. Delivery to a phone is the last three patches, not the first.

Two things make this phase unlike the others. It is **the first place a private
key crosses the wire** — out of escrow, to an agent, into a card — so 0093's
redaction and 0045a's disclosure events are preconditions rather than polish.
And it makes **attestation optional per profile**, which is the rule every
issuance so far has depended on; 0094 does it with a flag a reviewer can see
rather than with a slot number.

| # | Patch | DoD |
|---|---|---|
| 0091 | A cardholder has a mail address | `Cardholder.Mail` is read from the directory `mail` attribute at onboarding, stored, shown and editable in the panel. Onboarding a person with no address for an S/MIME profile is refused **at onboarding** with that reason, the way a missing `objectSid` already is. Schema regenerated by `SchemaTool`, not edited |
| 0092 | `smime-signing` onto `9C` | A key generated on the card and attested, as `9A` is. `digitalSignature` and `nonRepudiation`, EKU `1.3.6.1.5.5.7.3.4`, RFC 822 SAN from 0091, PIN policy *Always*. Issued by the built-in CA and, through a mapped template, by ADCS. Checked when Outlook on a domain workstation signs a message with the card and a second client verifies it, and `certutil -dump` shows the fields above. Key usage stops being derived from the slot in this patch |
| 0093 | `IMPORT ASYMMETRIC KEY` in `Blinky.Piv` | `INS FE` for RSA 2048 and P-256, under the authenticated management key. `0xFE` is in `ApduRedaction.CarriesASecret` **before** the first import is sent, with a test beside the existing redaction tests. Proved on a YubiKey 5.8: an imported RSA key in `9D` decrypts a CMS message encrypted to it, and attesting that slot is refused by the card and recorded as `KeyOrigin=Escrowed`, not as a failure |
| 0094 | `smime-encryption` onto `9D`, from escrow | Key generated centrally and sealed by 0045a before the CA is called; the step names the envelope, never the key; the agent fetches it once over mTLS, imports with 0093 and zeroises it; the disclosure is an audit event. The attestation check is replaced, for a profile with `KeyOrigin=Escrowed` only, by a match against that envelope. `keyEncipherment` for RSA, `keyAgreement` for EC. **Checked when** Outlook decrypts a message encrypted to the card, the card is reset and a replacement is issued from escrow, and the same message still decrypts. The ADCS template has archival off, or registration (0033) says why it will fail |
| 0095 | Workspace ONE UEM as a configured integration — both | `MdmIntegration` with full CRUD in the panel: API URL, token URL, OAuth client, organisation group, the secret write-only and stored as an envelope. A check endpoint obtains a token and resolves a known enrollment user by name, and reports each failure with its reason. The API never returns the secret |
| 0096 | The phone's own signing certificate | `smime-signing-mobile`: key generated centrally, not escrowed, not kept after delivery, `digitalSignature` without `nonRepudiation`. A `Credential` with a cardholder and container `MdmUser` and no token. Revoking or terminating the card (0043) revokes it, and the CRL says so |
| 0097 | S/MIME delivered to UEM | `uploadsmimecerts` with the current encryption key, **every archived generation** and 0096's certificate, triggered by issuance, renewal, `9D` rotation and UEM's device-enrolled notification. One `MdmDelivery` row and one disclosure event per upload. Checked on a managed Android in Boxer: a message **encrypted to the card before the phone was enrolled** decrypts, and a reply signed on the phone verifies on the desktop. Same on iOS. After a second upload the oldest archived message still decrypts on the phone, which is the check that the archived parameter really works |

**Phase gate:** one person, one mailbox. Outlook on Windows signs and decrypts
with the card; Boxer on a UEM-managed phone reads a message encrypted to that
card before the phone existed and signs a reply the desktop accepts; a lost
card is replaced from escrow and the old mail still opens on both; and
terminating the person revokes the card's certificates and the phone's
together.

## Later

Named so they are not mistaken for oversights: OCSP responder, SCP03/SCP11
secure channel, dual control for privileged profiles, hash-linked audit chain,
non-Yubico token support. The Windows credential provider has moved up to 0049a
now that there is a reason for it.

### FIDO2 — now Phase 7

Listed here as three tasks and not a commitment. It is a commitment: the three
became Phase 7 above, and the brief they came from is
[12](12-passkey-provisioning-brief.md). What this section said about Okta —
"narrower, and may come down to a guided browser ceremony" — turned out to be
wrong, and is worth recording as wrong rather than quietly deleting: Okta
enrols a security key on a user's behalf through its own management API, its
Admin Console does it by hand already, and the agent-side ceremony is the same
one Entra needs. It is a second implementation of one interface, not a second
design.

### Google Workspace — analysed, not scheduled

There is **no public Google API that accepts a WebAuthn attestation on behalf
of a user**. This is not an agent limitation — the agent could run
`makeCredential` against rpId `google.com` perfectly well — there is simply no
endpoint to hand the result to, so the first and third steps of the flow do not
exist. The admin-side APIs cover policy and reporting only.

Two answers, and the second is usually the real one:

- **Prepare-only.** Blinky sets the FIDO2 PIN with `forceChangePin`, records the
  key against a cardholder, prints a hand-off sheet, and then watches the
  Directory API's read-only enrolment signals to see whether the user ever
  enrolled. That is a compliance loop rather than provisioning, and it is
  optional; brief §7 holds the design.
- **Federate.** Front Google with Entra or Okta and provision at the IdP.
  Phishing-resistant sign-in to Google, with no Google-side enrolment at all.

Phases 0070–0079 owe this exactly two things, both nearly free and both already
in the DoD of 0073 and 0078: the capability flags exist from the first commit,
and the selector shows an unsupported provider with a reason instead of
omitting it.
## 0025 — card personalisation (management key, PIN, PUK)

The building blocks exist and nothing uses them. `PivPinOperations` already has
CHANGE REFERENCE DATA and RESET RETRY COUNTER, so PIN and PUK changes are
written and tested; `PukEscrow` already does checkout, commit and offline
unblock. The enrolment flow calls none of it, so every card Blinky has ever
issued to still carries the factory PIN `123456`, the factory PUK `12345678`
and the factory management key.

What is actually missing:

- **SET MANAGEMENT KEY (`INS 0xFF`)** — the one PIV instruction not implemented.
- **Writing** the PRINTED object. Reading it landed with the protected-key
  work; writing is the other half.
- **A policy decision, which is the real work.** A management key can be random
  per card and escrowed on the server, or random per card and kept on the card
  behind the PIN. The second is the convention the YubiKey minidriver uses, so
  choosing it means Blinky and that driver stop taking the card away from each
  other — see below for why that matters.

Until this lands, a card is protected by values printed in every manual.

## Off the vendor minidriver — OpenSC

Windows' inbox PIV minidriver would not produce a key container for a card that
met every requirement in SP 800-73 that could be checked: CHUID present, unique
and well-formed; CCC byte-identical in structure to Yubico's own; certificate
object encoded `70 … 71 01 00 FE 00`; RSA 2048; the certificate's public key
matching the key in the slot, proven by attestation. `certutil -scinfo`
answered `NTE_BAD_KEYSET` on both providers throughout. Installing Yubico's
minidriver fixed it immediately.

Why that is not a good place to stop: the same driver takes ownership of the
card. It replaces the management key with a random one, hides it behind the
PIN, and blocks the PUK. So the driver that makes logon work is the driver that
takes the card away from the CMS.

**OpenSC** implements a Windows smart card minidriver alongside its PKCS#11
module, supports the PIV applet generally rather than one vendor's, and does
not claim ownership of a card. It is also open source, which matters here for a
reason beyond licence: several hours went into a failure whose cause is inside
`msclmd.dll` and cannot be read.

The task is to test it: install the OpenSC minidriver on a clean workstation,
issue, and attempt logon. If it works, it replaces a vendor dependency with a
portable one and removes the management-key conflict at its source.

**The risk is worth stating plainly.** Nobody has established *why* the inbox
driver refuses. If the cause is something about the YubiKey applet rather than
about Microsoft's driver, OpenSC may refuse for the same reason, and the answer
becomes "a vendor minidriver is a prerequisite" — which is a legitimate
finding, but only after it has been tested rather than assumed.

## Linux: where smart-card login stopped, 2026-08-24

Kerberos and the card are fine. What is not resolved is sssd.

**What works.** `BY-LX-Client01` is joined, resolves domain users, and reads the
card: `pcscd` sees the reader, OpenSC and Yubico's `libykcs11` both enumerate
the token, and the certificate on it is correct in every respect that matters -
`Digital Signature` key usage, `clientAuth` and `msScLogin` EKUs, the UPN in an
otherName, the SID extension, and a chain that `openssl verify` accepts against
the same CA database sssd was given.

**What does not.** `sssd`'s `p11_child` finds the certificate, logs
`found cert[Certificate for PIV Authentication][/CN=Jan Nowak]`, skips OCSP
because there is no responder, and then reports `No certificate found` and
returns zero. The greeter and `sssctl user-checks jnowak -s gdm-smartcard -a
auth` both end at `Please (re)insert (different) Smartcard`.

Four causes were ruled out by test rather than by reasoning:

- **Trust.** `openssl verify` against `/etc/sssd/pki/sssd_auth_ca_db.pem`
  returns OK.
- **Verification itself.** `p11_child --verify=no_verification` returns zero
  just the same.
- **The PKCS#11 module.** OpenSC and `libykcs11` behave identically.
- **Privilege.** sssd and `p11_child` both run as root; the polkit rule that
  the reader needs over SSH is irrelevant here.

So the certificate is dropped somewhere between passing OCSP and the end of
`read_certs`, without a message. That is a narrow place to start: sssd source
for that function, and `p11_child` at debug level 10.

**A hazard found the hard way.** The PAM profile that makes this work,
`sss-smart-card-optional`, puts `pam_sss` with `try_cert_auth` ahead of the
password. With a card in the reader the greeter enters card mode and does not
return to a password, so a machine set up this way and left with a card in it
is a machine nobody can log into. "Optional" describes what PAM does with the
result, not what the person at the screen is offered. `install-linux-client.sh`
now puts this behind `--smartcard-login` rather than `--anchors`, checks that
the password path survived, and reverts if it did not.

**Not attempted yet.** `kinit -X` with the card - the cheaper rung of the same
ladder, which would prove the KDC accepts the certificate without PAM or a
greeter in the way. Worth doing first next time, because it separates the
certificate and the KDC from everything sssd does with them.

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
6. **Does the lab get an Entra tenant and an Okta org?** Phase 7's contract
   tests need neither — recorded fixtures cover both providers, and 0076 can be
   proved against a mock relying party. Everything past that needs a real
   tenant and a real org, which no script here can provision and which nobody
   has yet agreed to pay for. Decide before 0076, not after.
7. **Google Workspace: prepare-only, or federation and nothing else?** There is
   no API to register a passkey on a user's behalf, so the choice is between a
   compliance loop that presets the PIN and watches for self-enrolment, and
   telling operators plainly to front Google with an IdP that does have one. A
   product decision; the technical answer is already written in brief §7.
8. **May escrowed encryption keys rest in Workspace ONE UEM SaaS?** 0097's
   upload path puts every generation there. If not, Credential Escrow Gateway —
   which needs Omnissa Professional Services before it needs code. Decide
   before 0097. See [16](16-smime-card-and-mobile.md#open-questions).
9. **How do senders find a cardholder's encryption certificate?** On-premises
   Exchange reads `userCertificate`, which is 0035 and deferred; Exchange
   Online gets it by directory sync. Without either, encryption works only
   after the recipient has signed a message first.
