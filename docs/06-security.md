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
| 5 | Stolen agent certificate | 90-day lifetime, automatic rotation, revocable from the console. Grants only the ability to ask for work, never to authorise it |
| 6 | Stolen bootstrap token | Single-use, rate-limited, per-deployment, revocable. Buys one agent certificate |
| 7 | Management key extracted from one token | Keys are per-token derived from an HSM-resident master. One token's key opens one token |
| 8 | Database stolen | No PINs anywhere, no management keys (derived, not stored), PUKs encrypted under an HSM-held KEK with the serial as AAD |
| 9 | Orphaned certificate — CA signed, card never received it | The `Issued`/`Installed` split makes it a visible state; the reconciler retries or revokes |
| 10 | Certificate that logs in as the wrong person | SID extension emitted by the built-in CA; the ADCS backend refuses templates configured to supply the subject in the request. See [04](04-pki-backends.md#strong-certificate-mapping) |
| 11 | Silent replacement of a Blinky-issued credential | Inventory compares slot contents against the recorded public-key hash; a mismatch marks the slot `Stale` and raises it rather than overwriting |
| 12 | PUK disclosure by an insider | Every decryption of an escrowed PUK writes an audit event exempt from retention, and is a designed alerting trigger |
| 13 | Denial of service by PIN blocking | PIN retry counters are read on every contact and surfaced before they reach zero; the unblock workflow is deliberately cheap |

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
- **A compromised domain controller defeats everything.** Identity comes from
  the directory; if the directory lies, Blinky faithfully certifies the lie.
- **Physical possession plus a known PIN is authentication.** Touch policy
  raises the bar to physical presence per operation; it does not change the
  model.

## Hardening not in v1

Tracked, not built, and named here so nobody assumes otherwise:

- OCSP responder (CRL only at first).
- SCP03/SCP11 secure channel to the token, which would protect the management
  key against a compromised host between agent and reader. Firmware-dependent
  and needs verification on the target hardware before it is promised.
- Dual control for issuance — two operators for privileged profiles.
- Tamper-evident audit chain (hash-linked events).
- FIPS-mode token enforcement as a policy condition.
