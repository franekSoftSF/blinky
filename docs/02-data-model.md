# 02 — Data model

PostgreSQL, NHibernate, one schema. Structured columns for anything queried or
joined; `jsonb` for payloads whose shape belongs to a protocol version rather
than to the database.

## Entities

| Entity | Key | What it is |
|---|---|---|
| `Cardholder` | `id` | The person a credential belongs to, plus the directory reference used to resolve them |
| `Token` | `id`, unique `serial` | One physical YubiKey. Serial is the identity; the row outlives any credential on it |
| `Slot` | `(token_id, slot_id)` | One PIV slot on that token. Fixed set of rows created when the token is registered |
| `Credential` | `id` | One issued certificate bound to one slot. Immutable once issued — renewal creates a new row |
| `CertificateProfile` | `id` | What to issue: algorithm, EKUs, subject/SAN template, validity, PIN and touch policy, CA backend, ADCS template name |
| `IssuancePolicy` | `id` | Who gets which profiles, and under what conditions |
| `CaInstance` | `id` | A configured CA: backend, config, chain, CRL/OCSP URLs |
| `Job` | `id` | One unit of work for one agent |
| `Agent` | `id` | One installed workstation agent |
| `SecretEnvelope` | `id` | Encrypted material at rest — PUK escrow, and management keys where not derivable |
| `AuditEvent` | `id` | Append-only record of everything that changed state |

### `Cardholder`

```
id                uuid
display_name      text
upn               text            -- user@realm
object_sid        text            -- AD/Samba4 SID; needed for strong cert mapping
distinguished_name text
directory_source  text            -- 'ad' | 'samba4' | 'local'
state             text            -- Active | Suspended | Offboarded
created_at, updated_at  timestamptz
```

`object_sid` is not optional in an AD or Samba4 deployment, and the reason is in
[04 — PKI backends](04-pki-backends.md#strong-certificate-mapping): since the
KB5014754 enforcement change, a smart-card logon certificate without the SID
extension will not authenticate a user unless an explicit `altSecurityIdentities`
mapping exists. Resolving the SID at cardholder creation, not at issuance time,
means the failure surfaces during onboarding rather than three weeks later when
somebody's key stops working.

### `Token`

```
id                    uuid
serial                bigint UNIQUE   -- YubiKey serial, from the attestation cert
firmware_version      text            -- '5.4.3'
form_factor           text            -- from attestation extension 1.3.6.1.4.1.41482.13.4
attestation_thumbprint text           -- F9 slot cert, pinned at registration
state                 text            -- see lifecycle below
cardholder_id         uuid NULL
mgmt_key_algorithm    text            -- 'TDES' | 'AES192' | 'AES256'
mgmt_key_version      int             -- which derivation generation is on the card
mgmt_key_state        text            -- Default | Diversified | Unknown | Lost
pin_state             text            -- Default | UserSet | Blocked
puk_state             text            -- Default | Escrowed | Blocked | Disabled
pin_retries_left      smallint
puk_retries_left      smallint
last_seen_at          timestamptz
last_seen_agent_id    uuid NULL
```

`mgmt_key_state` deserves its own field rather than being inferred. A token
whose management key is neither the factory default nor the value Blinky would
derive is **unmanageable** — no key generation, no certificate write — and that
is an operational condition an operator has to see in a list, not discover in a
failed job.

### `Slot`

```
token_id     uuid
slot_id      text        -- '9A' | '9C' | '9D' | '9E' | '82'..'95'
state        text        -- Empty | KeyPresent | Provisioned | Stale
credential_id uuid NULL  -- current occupant
key_algorithm text NULL
touch_policy  text NULL  -- Never | Always | Cached
pin_policy    text NULL  -- Never | Once | Always
```

`Stale` means the card holds a key or certificate that Blinky did not put there
or no longer recognises. It is a first-class state because it is what you find
on every token that was ever touched by `ykman` — and silently overwriting it is
the wrong default.

### `Credential`

```
id                 uuid
token_id           uuid
slot_id            text
profile_id         uuid
ca_instance_id     uuid
serial_number      text          -- certificate serial, hex
issuer_dn          text
subject_dn         text
not_before         timestamptz
not_after          timestamptz
public_key_sha256  bytea         -- binds the certificate to the attested key
attestation_id     uuid          -- the verified chain that authorised issuance
state              text          -- see lifecycle below
supersedes_id      uuid NULL     -- renewal chain
revocation_reason  text NULL
revoked_at         timestamptz NULL
```

`public_key_sha256` is the join between "what the CA signed" and "what the card
proved it holds". Renewal, revocation and the stale-slot detector all key off
it rather than off the certificate serial, because the serial is the CA's
opinion and the public key is the card's.

### `Job`

```
id                uuid
type              text        -- Enroll | Renew | Revoke | UnblockPin | ResetCard | Inventory | RotateMgmtKey
token_serial      bigint NULL
agent_id          uuid NULL
cardholder_id     uuid NULL
state             text
attempt           int
idempotency_key   text UNIQUE
payload           jsonb       -- protocol-versioned, see 05
result            jsonb NULL
lease_expires_at  timestamptz NULL
deadline_at       timestamptz
created_at, updated_at timestamptz
```

## Three state machines

Keeping them separate is deliberate. A token can be perfectly healthy while a
credential on it is revoked, and a job can fail without either of them moving.

### Token lifecycle

```
Detected ─► Registered ─► Personalised ─► Assigned ─► Active
                │              │                        │
                │              │                        ├─► Suspended ─► Active
                │              │                        │
                │              │                        ├─► Lost / Stolen ─┐
                │              │                        │                  │
                │              └────────────────────────┴─► Terminated ◄───┘
                │                                                 │
                └─► Rejected (attestation failed)                 ▼
                                                               Retired
```

- **Detected** — an agent saw a serial that is not in the database.
- **Registered** — attestation verified, chain pinned, inventory recorded.
- **Personalised** — management key diversified, PUK escrowed, PIN policy applied.
  This is the step that takes the token away from factory defaults; nothing is
  issued before it.
- **Assigned** — bound to a cardholder.
- **Terminated** — every credential revoked. Distinct from **Retired**, which
  additionally means the token was physically recovered and wiped.

`Lost`/`Stolen` triggers mass revocation but does *not* wipe: the card is not in
hand, so the only truthful statement is "its certificates are dead".

### Credential lifecycle

```
Requested ─► KeyGenerated ─► CsrSubmitted ─► Issued ─► Installed ─► Active
    │             │               │            │           │           │
    │             │               │            │           │           ├─► Expiring
    │             │               │            │           │           │      │
    │             │               │            │           │           │      ▼
    │             │               │            │           │           │   Superseded
    │             │               │            │           │           │
    │             │               │            │           │           ├─► Revoked
    │             │               │            │           │           │
    │             │               │            │           │           └─► Expired
    └─────────────┴───────────────┴────────────┴───────────┴─► Failed
```

`Issued` and `Installed` are two states, not one, and that gap is the single
most useful thing in this diagram. The CA has signed a certificate; the card
does not have it yet. If the agent dies in between, there is a live certificate
in the CA's database with no matching key holder — and Blinky knows, because the
row is stuck in `Issued`. The worker's reconciler either retries installation or
revokes the orphan. Merging the two states would make that class of leak
invisible. Same reasoning as FAG's two record counters.

### Job lifecycle

```
Pending ─► Dispatched ─► Claimed ─► Running ─► Succeeded
   │           │            │          │
   │           │            │          ├─► AwaitingUser ─► Running
   │           │            │          │
   │           │            │          └─► Failed ─► Pending (retry, attempt+1)
   │           │            │                  │
   │           │            └──────────────────┴─► Expired (deadline or lease lost)
   │           │
   └───────────┴─► Cancelled
```

`AwaitingUser` exists because a job blocked on "touch your key" is not stuck and
must not count against the lease timeout the same way a hung APDU does. It has
its own, much longer, deadline.

Leases, not locks: a claimed job carries `lease_expires_at`, and the worker's
watchdog returns expired leases to `Pending`. An agent that loses power mid-job
does not leave work permanently claimed.

## Secrets at rest

Three different problems, three different answers.

**PIN — never stored.** Not encrypted, not hashed, not in a log, not in a job
payload that touches the database. It exists in the agent's memory for the
duration of one APDU and is zeroed. If a workflow appears to need a stored PIN,
the workflow is wrong.

**Management key — derived, not stored.**

```
mgmt_key = HKDF-SHA256(
    ikm  = master_key,                        -- lives in PKCS#11 / HSM, never exported
    salt = "blinky.piv.mgmt.v1",
    info = serial || ":" || mgmt_key_version
)[0..24]                                      -- AES-192
```

Per-token diversification means compromising one token's key yields exactly one
token. Nothing needs a row in the database except the *version*, so the table
holds no key material at all. Rotation is a version bump plus one job. The
master key is the single thing whose loss is unrecoverable, and it is therefore
the single thing in an HSM.

Note the algorithm field on `Token`: YubiKey firmware before 5.7 ships a 3DES
management key and 5.7 or later ships AES-192. The agent reads the actual
algorithm via the metadata command rather than assuming — see
[03 — PIV layer](03-piv-layer.md#management-key).

**PUK — escrowed, encrypted, envelope-wrapped.**

```
SecretEnvelope
  id, token_id, kind='puk', key_version,
  ciphertext bytea,          -- AES-256-GCM
  nonce bytea, tag bytea,
  aad = 'puk|' || serial     -- binds the ciphertext to one token
```

The PUK cannot be derived, because unblocking has to work when an operator is
reading it off a screen to a user on the phone. So it is random per token,
encrypted under a KEK that lives in the same HSM as the master key, and every
decryption writes an `AuditEvent`. Reading a PUK is an event worth alerting on.

## Storage notes

- Schema created by `docker/postgres/001-schema.sql`, which runs only against an
  empty data directory. Changing it means `docker compose down -v` or a manual
  `ALTER TABLE`.
- `SchemaValidator` runs at service start and compares mappings against the live
  schema. It **logs and continues** rather than killing the process — a missing
  column should produce one readable line, not a restart loop with no
  explanation. Ported wholesale from FAG.
- `jsonb` columns are mapped with `.CustomSqlType("jsonb")`; NHibernate will
  otherwise infer `text` and comparisons will quietly stop working.
- `AuditEvent` is append-only and partitioned by month. Retention is a policy
  setting, but revocation and PUK-disclosure events are exempt from it.
