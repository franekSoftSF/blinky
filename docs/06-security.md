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
| 14 | Denial of service by PIN blocking | PIN retry counters are read on every contact and surfaced before they reach zero; the unblock workflow is deliberately cheap |

## Key custody

Three secrets, in descending order of how bad it is to lose them:

1. **The CA issuing key.** In the HSM in production, SoftHSM in the compose
   default, and a file only when `Blinky:Ca:AllowFileKeys` is explicitly set.
   Compromise means arbitrary certificates the domain trusts.
2. **The management-key master.** HSM-resident, never exported. Compromise means
   every managed token can be reprogrammed. Its derivation is versioned so
   rotation is a version bump and a job per token, not a fleet rebuild.
3. **The PUK KEK.** Same HSM. Compromise means every escrowed PUK.

The root CA key is not on this list because it is not in the system: generated
offline, used to sign the issuing CA, and stored off the host.

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
