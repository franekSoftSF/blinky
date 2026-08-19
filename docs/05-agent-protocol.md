# 05 — Agent protocol

REST over HTTPS for everything the agent initiates, one SignalR hub for the
doorbell. See [01 — Architecture](01-architecture.md#transport-https--signalr-not-a-broker)
for why there is no broker.

## Two identities, not one

Every request carries the **agent's** identity. Requests that act on a person
also carry that **person's** identity, and the two are verified independently.

| | Proves | Obtained by | Sent as |
|---|---|---|---|
| Agent identity | *which machine* | mTLS client certificate, issued at enrolment | TLS layer |
| User identity | *who is at the keyboard* | SPNEGO/Kerberos ticket from the interactive session | `Authorization: Negotiate …` |

`Agent.Service` runs as LocalSystem, so it can only ever prove the machine.
`Agent.Ui` runs as the user, so it is the only component that can produce the
second token — it fetches one on demand and hands it over the named pipe for a
single request. This is the whole reason the workstation has two processes.

An enrolment job for cardholder X is executed only if the user token resolves to
X, or if the caller holds an operator role and the job was created in the
console with an explicit override. "The agent said so" is never sufficient to
bind a credential to a person.

## Agent enrolment

```
MSI install ──► bootstrap token (per-deployment, in the MSI properties)
    │
    ▼
POST /api/agents/enroll        { hostname, domain, bootstrapToken, csr }
    │
    ▼
Api: validate token, create/lookup Agent by (hostname, domain), issue client cert
    │
    ▼
agent stores cert in LocalMachine\My, uses it for everything afterwards
```

The bootstrap token is single-purpose and rate-limited; it authorises exactly
one certificate issuance. Agent certificates are short-lived (90 days) and
renewed automatically over mTLS, so a leaked bootstrap token stops being useful
quickly and a leaked agent certificate expires on its own.

Registration is idempotent on `(hostname, domain)`. `domain` is a required MSI
property for the same reason as in FAG: LocalSystem's `UserDomainName` returns
the *machine* name, and guessing produces a second, orphaned agent row.

Agent identity survives uninstall — the GUID lives in
`ProgramData\Blinky\agent-id.txt`, outside the install directory — so a version
upgrade is not a new agent.

## REST surface

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/agents/enroll` | Bootstrap. The only unauthenticated endpoint |
| `POST` | `/api/agents/{id}/heartbeat` | Liveness, agent version, reader list |
| `POST` | `/api/agents/{id}/renew-certificate` | Rotate the client certificate |
| `GET` | `/api/jobs/next?agentId=` | Claim the next job; takes a lease |
| `POST` | `/api/jobs/{id}/progress` | State transitions, including `AwaitingUser` |
| `POST` | `/api/jobs/{id}/result` | Terminal outcome |
| `POST` | `/api/tokens/inventory` | Report what is in the reader |
| `POST` | `/api/credentials/issue` | Submit PKCS#10 + attestation, receive a certificate |
| `POST` | `/api/credentials/{id}/installed` | Confirm the certificate reached the card |
| `GET` | `/api/policy/for-token/{serial}` | What this token should look like |

`/api/credentials/issue` and `/api/credentials/{id}/installed` are separate calls
on purpose — that gap is the `Issued` → `Installed` transition from
[02 — Data model](02-data-model.md#credential-lifecycle), and collapsing them
would hide orphaned certificates.

## The doorbell

```
Hub:      /hubs/agents          (WSS, mTLS, agent identity from the certificate)
Server → agent:   WorkAvailable()          — no payload
Agent  → server:  Subscribe(agentId)
```

`WorkAvailable` carries nothing. The agent responds by calling
`GET /api/jobs/next`, which is the same call it makes on its polling timer.
Consequences:

- The hub can be down, flapping, or blocked by a proxy and the system still
  works — jobs are picked up on the next poll instead of within a second.
- There is no message to lose, deduplicate, or version. The database is the
  only source of truth about what work exists.
- Replacing SignalR with MQTT, SSE, or nothing at all touches one class per
  side.

Polling floor is 60 seconds when the hub is connected, 30 when it is not.

## Job envelope

```json
{
  "schemaVersion": 1,
  "jobId": "9c1f…",
  "type": "Enroll",
  "idempotencyKey": "enroll:12345678:9A:v3",
  "deadlineAt": "2026-08-19T11:40:00Z",
  "tokenSerial": 12345678,
  "cardholder": {
    "id": "3ab0…",
    "displayName": "Jan Kowalski",
    "upn": "jkowalski@corp.example"
  },
  "steps": [
    { "op": "RequireToken",       "serial": 12345678 },
    { "op": "VerifyUser",         "method": "auto" },
    { "op": "AuthenticateMgmtKey" },
    { "op": "GenerateKey",        "slot": "9A", "algorithm": "ECCP256",
                                  "pinPolicy": "Once", "touchPolicy": "Cached" },
    { "op": "Attest",             "slot": "9A" },
    { "op": "BuildAndSignCsr",    "slot": "9A", "profile": "smartcard-logon" },
    { "op": "SubmitToCa" },
    { "op": "WriteCertificate",   "slot": "9A" },
    { "op": "RefreshCertStore" }
  ]
}
```

The job is a **script**, not a verb. The server decides the sequence, the agent
executes it, and each step reports independently. Two reasons this beats a fat
`Enroll` command the agent interprets:

1. A failure names the step. "Enrolment failed" is not a diagnosis; "step 3
   `GenerateKey` returned `6982`" is.
2. Changing the sequence — adding a management-key rotation before generation,
   splitting touch-requiring operations — is a server-side change that reaches
   the whole fleet without shipping a new agent.

`VerifyUser` with `method: "auto"` is resolved by the agent against the card,
not by the server against a database row: a Bio Multi-protocol token asks for a
fingerprint, everything else asks for a PIN, and a Bio whose match attempts are
exhausted falls back to a PIN. The server records which method was actually
used; it does not decide it. See
[03 — PIV layer](03-piv-layer.md#biometric-verification--bio-multi-protocol-edition).

The agent refuses any `op` it does not know rather than skipping it, and reports
`UnsupportedOperation` with its own version so the mismatch is visible in the
console.

## Idempotency and delivery

Delivery is **at least once**; execution must be **at most once** where it
matters.

- `idempotencyKey` is unique in the database. Re-creating the same logical job
  returns the existing one instead of a second row.
- `GET /api/jobs/next` takes a **lease**, not a lock. The worker's watchdog
  returns expired leases to `Pending`. A workstation that loses power does not
  leave a job claimed forever.
- Result submission is idempotent by `(jobId, attempt)`. A retried
  `POST /result` after a network timeout is a no-op, not a second outcome.
- Steps with side effects on the card carry their own guard. `GenerateKey`
  checks slot state first: if a key already exists whose public key matches the
  one recorded for this attempt, the step is already done and reports success
  rather than generating a second key and orphaning the first.

That last one is the important one. Retrying a key generation is not free — it
destroys the previous key — so the guard is in the agent, not just in the
server's retry policy.

## Offline behaviour

The agent keeps working when the backend is unreachable:

- Inventory results queue to disk (capped, oldest dropped) and flush on
  reconnect.
- A job already in flight runs to completion; only the result upload waits.
- Nothing that requires the CA is attempted offline, and the user is told that
  in those words rather than being shown a generic failure.

The agent never caches a management key, a PIN, or a PUK to survive an outage.
Offline enrolment is not a feature and is not going to be one.

## Versioning

`schemaVersion` on every envelope. The rule is additive: new optional fields do
not bump it, removals and semantic changes do. The API advertises the range it
speaks in the heartbeat response, and an agent outside that range is marked
`Incompatible` in the console and receives no jobs — rather than receiving jobs
it will half-understand.
