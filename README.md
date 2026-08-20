# Blinky

**Your key blinks. Blinky is why.**

An open-source **credential management system** for YubiKey 5 PIV, built on
.NET 10, Angular and Docker.

Blinky owns the full lifecycle of a smart-card credential — issue, renew,
revoke, unblock, retire — with the private key **generated on the token and
never leaving it**. It is not a wrapper around a commercial CMS; it is the CMS.

Two CA backends sit behind one interface:

- a **built-in CA** that runs inside the compose stack (no AD required), and
- **Microsoft ADCS** driven through an enrolment agent ("enrol on behalf of").

Same workflows, same audit trail, whether the directory is Windows AD or
Samba4.

> Blinky is an independent open-source project. It is not affiliated with,
> endorsed by, or supported by Yubico. "YubiKey" and "PIV" are used
> descriptively to identify the hardware and the standard this software
> targets.

```
                   Docker host
┌─────────────────────────────────────────────────────┐
│  frontend (Angular 22 + nginx)                      │
│       │ /api                                        │
│       ▼                                             │
│  Blinky.Api ───────► PostgreSQL                     │
│    │  ▲  │                                          │
│    │  │  └───────► Blinky.Worker (jobs, CRL, expiry)│
│    │  │                                             │
│    │  │            Blinky.Pki                       │
│    │  │             ├─ BuiltInCa ──► SoftHSM / PKCS#11
│    │  │             └─ AdcsCa ─────► CES/CEP (HTTPS)
│    │  │                        └───► AdcsConnector (Windows, DCOM)
└────┼──┼─────────────────────────────────────────────┘
     │  │ HTTPS + WSS (SignalR)
     ▼  │
┌───────┴─────────────────────────────────────────────┐
│  Workstation                                        │
│                                                     │
│  Agent.Service (LocalSystem) ─► PC/SC ─► YubiKey 5  │
│       │ named pipe                       PIV applet │
│  Agent.Ui (user session)                            │
│       PIN prompt · touch prompt · Kerberos auth     │
└─────────────────────────────────────────────────────┘
```

## What it does

- **Inventories tokens.** Serial, firmware, form factor, slot occupancy, PIN
  retry counters, management-key state — read straight off the card over PC/SC.
- **Issues credentials.** Key generated in slot `9A`/`9C`/`9D`/`9E`, CSR signed
  by the card, certificate issued by the selected CA backend and written back
  with `PUT DATA`.
- **Proves the key is on hardware.** Every issuance verifies a Yubico
  attestation certificate chained to the Yubico PIV Attestation CA before the
  CA is asked to sign anything.
- **Takes the card away from its defaults.** Default management key, PIN and
  PUK are rotated at first contact; the management key becomes a per-card
  diversified value, the PUK is escrowed encrypted.
- **Runs the boring lifecycle.** Expiry scanning, scheduled renewal, revocation
  with CRL/OCSP publication, PIN unblock, retirement and key archival policy.
- **Keeps an audit trail** that survives the card being lost.

## Components

| Project | Type | Runs on | Purpose |
|---|---|---|---|
| `Blinky.Contracts` | class lib | — | Job envelopes, enums, protocol versioning |
| `Blinky.Domain` | class lib | — | Cards, cardholders, credentials, policy, state machines |
| `Blinky.Infrastructure` | class lib | — | NHibernate mappings, PostgreSQL |
| `Blinky.Piv` | class lib | — | PC/SC transport, PIV APDUs, Yubico extensions |
| `Blinky.Pki` | class lib | — | `ICertificateAuthority` + both backends |
| `Blinky.Api` | ASP.NET Core | docker | REST, SignalR hub, Angular's backend |
| `Blinky.Worker` | Worker Service | docker | Job engine, CRL/OCSP, expiry scanner |
| `Blinky.Agent.Service` | Worker Service | workstation | Owns the reader, executes jobs |
| `Blinky.Agent.Ui` | WPF, per session | workstation | PIN/touch prompts, Kerberos auth |
| `Blinky.AdcsConnector` | Worker Service | Windows *(optional)* | DCOM `ICertRequest` bridge for shops without CES |

## Running

```bash
cp .env.example .env
./scripts/dev-certs.sh
docker compose up -d --build
./smoke-test.sh
```

| What | Where |
|---|---|
| Console (browser traffic, WAF blocking) | https://localhost:8443 |
| Agent API (mTLS, WAF in detection mode) | https://localhost:9443 |
| PostgreSQL | localhost:5432 |

The certificates are self-signed development material and `certs/` is ignored
by git. `api` is deliberately **not** published: the edge forwards the verified
client certificate as a header, which is only trustworthy because nothing else
can reach the API. PostgreSQL is published, because inspecting the database is
half of debugging.

The schema is generated from the NHibernate mappings rather than written by
hand, and both services compare the two at startup:

```bash
dotnet run --project tools/SchemaTool -- docker/postgres/001-schema.sql
```

It runs only against an empty data directory, so changing the schema means
`docker compose down -v` or a hand-written `ALTER`.

## Running on more than one machine

Everything above assumes one box. In a lab the backend, the agents and the
directory are separate machines, and three things change.

On the machine that runs the stack, name it in the certificate:

```bash
./scripts/dev-certs.sh --force --host blinky.lab --host 10.0.0.5
docker compose up -d --build
```

Every `--host` becomes a subject alternative name. `localhost` and `127.0.0.1`
are always included, so the stack keeps working from its own console.

On each agent machine, copy `certs/dev-ca.crt` across and point the agent at
it:

```
Agent__BackendUrl=https://blinky.lab:9443
Agent__Domain=corp.example
Agent__BootstrapToken=<from .env>
Agent__ServerCertificateAuthorityPath=C:\ProgramData\Blinky\dev-ca.crt
```

`Agent__AcceptAnyServerCertificate` exists for a single-machine bench and
checks nothing. Once the backend is somewhere else, pin the CA instead — the
agent logs a warning if it is running without one.

And point the checks at the right host:

```bash
BLINKY_HOST=blinky.lab ./smoke-test.sh
```

**Regenerating certificates means restarting.** `api` loads the agent CA at
startup and nginx loads its own certificate at startup, so both need a restart
after `dev-certs.sh --force` — and every agent certificate issued by the
previous CA stops being accepted.

## Building

```bash
dotnet build Blinky.slnx
dotnet test Blinky.slnx
```

`Blinky.slnx` is the new XML solution format (Visual Studio 17.13+, Rider
2024.3+). The solution must be built on Windows: `Blinky.Agent.Ui` is WPF and
`Blinky.AdcsConnector` targets `net10.0-windows` for DCOM. The containerised
projects — `Blinky.Api`, `Blinky.Worker` and the libraries below them — target
plain `net10.0` and build anywhere.

Package versions are managed centrally in `Directory.Packages.props`; no
`PackageReference` carries its own `Version`.

There is one tool outside the product:

```bash
dotnet run --project tools/PivProbe -- transcript.json
```

`tools/PivProbe` reads a YubiKey over PC/SC and prints what is on it. It is
read-only — no PIN verification with a real PIN, no key generation, no writes
of any kind — and it records the APDU transcript the `Blinky.Piv` tests replay.
Transcripts carry the token serial and any certificate on the card, so they are
not committed.

```bash
dotnet run --project tools/InsProbe
```

`tools/InsProbe` asks a card whether it understands an instruction, with a
control instruction whose answer is already known. It is what settled which
commands are standard PIV and which are Yubico's — see
[08 — What the hardware changed](docs/08-hardware-notes.md).

## Stack

.NET 10 · ASP.NET Core + SignalR · NHibernate · PostgreSQL · Angular 22 ·
PCSC-sharp with hand-rolled PIV APDUs · BouncyCastle (CMC, PKCS#7) ·
SoftHSM2 / PKCS#11 · WPF for the workstation UI · Serilog · Docker Compose

## Documentation

| Doc | Contents |
|---|---|
| [01 — Architecture](docs/01-architecture.md) | Component boundaries, process model, transport decision |
| [02 — Data model](docs/02-data-model.md) | Entities, three state machines, storage, secrets at rest |
| [03 — PIV layer](docs/03-piv-layer.md) | PC/SC, slots, APDUs, attestation, management key, error map |
| [04 — PKI backends](docs/04-pki-backends.md) | Built-in CA, ADCS enrolment agent, Samba4 variant |
| [05 — Agent protocol](docs/05-agent-protocol.md) | REST + SignalR contract, job envelopes, idempotency |
| [06 — Security](docs/06-security.md) | Trust boundaries, key custody, threat notes |
| [07 — Roadmap](docs/07-roadmap.md) | Phases, numbered patches, definition of done |
| [08 — What the hardware changed](docs/08-hardware-notes.md) | Every rule that came from a measurement rather than from reading |
| [09 — The test lab](docs/09-lab.md) | The four machines, what each one proves, and the traps in advance |
| [Status](docs/STATUS.md) | What is done, what is only written, and what is blocked |

## Why "Blinky"

Because that is the entire user experience, and the name should say so.

A YubiKey with a touch policy does exactly one thing to get your attention: it
blinks. Every credential this system issues passes through that blink at least
once — key generation on the token, the CSR signature, later every
authentication. The blink is the moment the abstraction stops being software
and becomes a piece of metal in a USB port that will not proceed without a
human finger. That moment is the product.

Three practical reasons on top of the joke:

- **It is what the user sees.** Support calls start with "it's flashing at me
  again". A name that matches the symptom shortens every conversation.
- **It is six letters.** The name gets typed into a browser, a terminal and a
  ticket title dozens of times a day. `blinky enroll` beats
  `pivforge-cms enroll`, and there is nothing in it to misspell.
- **It contains no "Yubi", no "HID", no "PIV".** No trademark to borrow, and no
  promise that the project is limited to one vendor's token or one standard if
  it later grows past both.

## Status

**Phase 1 complete — the gate is met.** Blinky reads tokens and tells the truth
about them: an agent enrols itself over mTLS, watches the readers, and reports
what it finds. Nothing is issued yet; that is Phase 2.

Per-patch progress, and an explicit list of what is written but **not yet
verified**, live in [docs/STATUS.md](docs/STATUS.md), with a machine-readable
copy in [docs/status.json](docs/status.json).

## Licence

[Apache-2.0](LICENSE). See [NOTICE](NOTICE) for trademark and third-party
dependency notes — in particular the NHibernate LGPL constraint on single-file
publishing.
