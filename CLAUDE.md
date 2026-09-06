# CLAUDE.md

Blinky — a credential management system for YubiKey 5 PIV. .NET 10, Angular,
Docker, PostgreSQL, NHibernate. Two CA backends behind one interface: a built-in
CA that runs in the compose stack, and Microsoft ADCS driven through an
enrolment agent. A workstation agent owns the reader and executes jobs.

Read [README.md](README.md) for what it is, [docs/](docs/) for how it works, and
[docs/STATUS.md](docs/STATUS.md) for what actually exists today. Do not infer the
state of a feature from the presence of code: several things are written,
unit-tested and never run against hardware, and the status files say which.

## The rule this repository is built on

**A patch is not done because the code exists. It is done when its definition of
done in [docs/07-roadmap.md](docs/07-roadmap.md) can be checked by somebody who
did not write it.** Six states are in use and they are not decoration:
`done`, `done-unverified`, `partly-done`, `open`, `blocked`, `deferred`. Writing
`done` for something that has never met hardware is the one thing that makes the
status files worthless.

When something cannot be proved here — no reader, no tenant, no Windows AD — say
so with the reason, in the patch's `gap`. "Blocked" with a written reason is a
good outcome; silence is not.

## Layout

| Path | What lives there |
|---|---|
| `src/Blinky.Contracts` | Job envelopes, enums, wire protocol version |
| `src/Blinky.Domain` | Entities, state machines, policy |
| `src/Blinky.Infrastructure` | NHibernate mappings, PostgreSQL, `SchemaValidator` |
| `src/Blinky.Piv` | PC/SC transport, PIV APDUs, Yubico extensions |
| `src/Blinky.Pki` | `ICertificateAuthority`, built-in CA and ADCS behind it |
| `src/Blinky.Directory` | LDAP reads — UPN and `objectSid`. Read-only by design |
| `src/Blinky.Api` | REST, SignalR hub, the console's backend |
| `src/Blinky.Worker` | Job engine, CRL/OCSP, expiry scanner |
| `src/Blinky.Agent.Service` | Workstation service (LocalSystem), owns the reader |
| `src/Blinky.Agent.Ui` | Tray and prompts, in the user's session |
| `src/Blinky.AdcsConnector` | DCOM `ICertRequest3`, `net10.0-windows` |
| `frontend/` | Angular console, pnpm |
| `tools/` | Probes and the schema generator, not shipped |
| `tests/Blinky.UnitTests` | xunit, one project, fixtures under `Fixtures/` |
| `scripts/` | Lab, CA and installer shell scripts — part of the product |
| `docs/` | Numbered design documents plus the two status files |

## Commands

```bash
dotnet build Blinky.slnx          # solution builds on Windows only: WPF + DCOM
dotnet test Blinky.slnx           # xunit, no hardware needed
docker compose up -d --build      # api, worker, postgres, console, edge
./smoke-test.sh                   # 13 checks against a running stack
BLINKY_HOST=blinky.lab ./smoke-test.sh
dotnet run --project tools/SchemaTool -- docker/postgres/001-schema.sql
dotnet run --project tools/PivProbe -- transcript.json   # read-only, real card
```

`frontend/` uses **pnpm**, not npm. CI (`.github/workflows/ci.yml`) runs on
`windows-latest` and does restore, build and test — nothing else.

## Conventions that are not negotiable

- **Package versions are central.** `Directory.Packages.props` holds every
  version; a `PackageReference` carries no `Version` attribute.
- **The schema is generated, never hand-edited.** Change a mapping, then run
  `tools/SchemaTool` to rewrite `docker/postgres/001-schema.sql`.
  `SchemaValidator` compares the two at service start, and PostgreSQL only runs
  the script against an empty data directory — a schema change means
  `docker compose down -v` or a hand-written `ALTER`.
- **Anything crossing the wire lives in `Blinky.Contracts`.** Additive changes
  do not touch `Protocol.SchemaVersion`; removals and semantic changes bump it,
  and a deployed agent must then refuse cleanly rather than misread a field.
- **`TreatWarningsAsErrors` and `Nullable` are on** for everything. A warning is
  a build failure; do not suppress one to get past it.
- **Serilog** everywhere. LF line endings, UTF-8, four spaces (two for
  json/yml/xml/props/csproj) — `.editorconfig` is authoritative.
- **Comments explain why, not what.** The existing ones state the reason a thing
  is the way it is, usually because the obvious alternative was tried and
  failed. Match that; do not add narration.

## Secrets, cards and other things that bite

- **A PIN must never reach a log, a message or a column.** `VERIFY` command
  bytes *are* the PIN — APDU logging is redacted by instruction, header kept.
  This was a real defect once (`jobs.result`, a column, a backup); do not undo
  it. `tests/.../ApduRedactionTests.cs` and `FixtureSafetyTests.cs` guard it.
- **A PUK is disclosed, not printed.** Every disclosure is an audit event with
  an actor and a reason, and the PUK is rotated straight after use.
- **Never write to a card outside a patch that is about writing to a card.**
  Phase 1 was built on the promise that nothing had touched a token, and the
  probes are read-only for that reason.
- **Untracked and irreplaceable:** `.env` (holds the management-key master and
  `PUK_KEK`), `ca/`, `certs/`, `.lab/`. They are gitignored on purpose. Do not
  commit them, and do not assume a fresh clone has them.
- The console still authenticates with one shared `X-Blinky-Operator` token.
  It is a known hole with a plan (0053a–e); do not build new things that depend
  on it lasting.

## Documentation is part of the change, not a follow-up

- Design documents are numbered in `docs/`. A change that contradicts one edits
  that document in the same commit.
- **`docs/STATUS.md` and `docs/status.json` must agree.** `status.json` is what
  a build or dashboard reads; `STATUS.md` is the same facts in prose. Update
  both, including `status.updated`, whenever a patch changes state. They have
  drifted before and it cost a day of re-deriving what was already known.
- Findings from hardware go to `docs/08-hardware-notes.md`; lab recipes to
  `docs/09-lab.md`. A thing that turned out to be wrong is recorded as wrong
  rather than quietly deleted.

## Commits

Subject: `NNNN: <one sentence saying what was actually wrong>`, where `NNNN` is
the patch number, or `docs:` / `status:` for documentation. Recent history is
Polish written without diacritics; older commits are English. The body explains
the real cause and what it cost — not a summary of the diff.

## Who writes what

`status.json` records an owner per patch: **codex** writes the Angular console,
**cloud-ai** writes the backend, the agent and the lab, **both** means it needs
one of each. Two worktrees under `.worktrees/` carry the console branches. Check
the owner before starting a patch that somebody else's branch is already inside.
