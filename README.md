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

**Phase 0 — design.** No production code yet. Per-component progress and the
next concrete actions live in [STATUS.md](STATUS.md), with a machine-readable
copy in [status.json](status.json).

## Licence

[Apache-2.0](LICENSE). See [NOTICE](NOTICE) for trademark and third-party
dependency notes — in particular the NHibernate LGPL constraint on single-file
publishing.
