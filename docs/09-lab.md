# 09 — The test lab

Four machines. Each one exists to prove something the others cannot, and the
list of what each one proves is the reason not to collapse them.

**This is a recipe, not a report.** The lab is being built; where a step has not
been run yet it says so. Findings from it belong in
[08 — What the hardware changed](08-hardware-notes.md), and the state of each
patch in [STATUS.md](STATUS.md).

## Why not one machine

Everything up to patch 0004 ran on a single laptop, and that hid three things
until the moment the machines were separated: the edge certificate said
`CN=localhost`, the agent trusted the backend by not checking it, and the smoke
test had `localhost` written into it. A single-box lab does not test the
architecture; it tests a special case of it.

| Machine | Role | What only it can prove |
|---|---|---|
| **blinky** | Docker host: `api`, `worker`, `postgres`, `edge` | That the backend works when it is not on the same machine as anything else |
| **dc** | Samba4 AD DC | That a certificate Blinky issued authenticates against a real KDC — the Phase 2 gate |
| **win** | Windows client, VMware, with the reader | Smart-card logon as a user actually experiences it, and the agent as a Windows service |
| **ubuntu** | Linux client | PKINIT without Windows in the way, and the pcsc-lite transport (patch 0017) |

## Order of setup

Each step depends on the one before it, and skipping ahead produces failures
that look like something else.

### 1. blinky — the Docker host

Name the host in the certificate, or nothing else will connect to it:

```bash
./scripts/dev-certs.sh --force --host blinky.lab --host 10.0.0.5
cp .env.example .env          # set BOOTSTRAP_TOKEN and the database password
docker compose up -d --build
BLINKY_HOST=blinky.lab ./smoke-test.sh
```

Ports the other machines need: **8443** console, **9443** agents. PostgreSQL on
5432 is published for inspection and does not need to leave the host.

Copy `certs/dev-ca.crt` off the machine — every client needs it.

### 2. dc — Samba4

Provision an AD DC in the usual way, then three things that are not optional
and are easy to get wrong:

- **Time.** Kerberos rejects a skew over five minutes, and the failure says
  nothing about clocks. Every machine in the lab syncs to the same source, the
  DC preferably.
- **DNS.** Every member machine must resolve the realm through the DC, not
  through the house router. Domain join fails in a way that reads like a
  network problem.
- **The realm name.** Pick it now and write it down; it ends up inside every
  certificate as a UPN suffix.

Publishing Blinky's CA into the directory, and issuing the KDC's PKINIT
certificate, is patch **0061** — `blinky-samba-setup`. Until that exists both
are manual LDAP writes, described in
[04 § The Samba4 variant](04-pki-backends.md#the-samba4-variant).

### 3. win — the Windows client

A VMware guest, joined to the domain, with the YubiKey passed through to it.

```
Agent__BackendUrl=https://blinky.lab:9443
Agent__Domain=corp.example
Agent__BootstrapToken=<from blinky's .env>
Agent__ServerCertificateAuthorityPath=C:\ProgramData\Blinky\dev-ca.crt
```

This is the first machine on which the agent runs as a Windows service rather
than from a console, which is what patch 0060 packages and what session 0
isolation is about — see [01](01-architecture.md).

**Keep it clean of other smart-card middleware.** On the development machine,
HID ActivClient is installed and Windows binds the YubiKey to *its* minidriver —
`certutil -scinfo` reports `Card: HID ActivClient (YubiKey 5)`. A certificate
written into a PIV slot then never reaches the user's certificate store,
because propagation goes through whichever minidriver claimed the card. This
does not affect Blinky's own reads and writes, which go straight to PC/SC, but
it does break the half of the story a user sees.

Do not join the machine you work on to the lab domain. The agent needs
`LocalSystem`, the reader, and a domain that will be rebuilt several times.

### 4. ubuntu — the Linux client

Two jobs, and neither needs a full VM if WSL2 is already present: `usbipd-win`
attaches a YubiKey to WSL2 in about ten minutes.

**PKINIT**, which proves the certificate authenticates without Windows
anywhere in the picture:

```bash
kinit -X X509_user_identity=PKCS11:/usr/lib/.../libykcs11.so user@REALM
```

If that succeeds, the parts Blinky is responsible for are right: EKUs, the UPN
SAN, the SID extension, the CA published into `NTAuthCertificates`, and the
KDC's own certificate. What remains after that is Windows client
configuration — real, but not issuance.

**pcsc-lite**, which is patch 0017. `pcscd` plus a reader, and the transport
gets its first test on a platform that is not Windows.

One thing to know before attaching: **while the token is attached to WSL it
disappears from Windows.** The Windows agent and `tools/PivProbe` stop seeing
it until it is detached.

## Two rungs, not one

The Phase 2 gate says "enrol a factory YubiKey and log into a Samba4 domain
with it". That needs `win` and `dc` both working, and it is the real gate.

There is a cheaper rung below it that needs only `dc` and `ubuntu`: **PKINIT
succeeds with a key on the token.** It proves every part of the certificate
Blinky produces, and it can be reached before the Windows guest exists. It is
worth reaching first, because when smart-card logon fails on Windows the
question is always "is it the certificate or the client?", and this answers it
in advance.

## Traps, collected in advance

| Symptom | Cause |
|---|---|
| Every enrolment returns 500 right after setting up | The agent CA was created minutes ago; fixed in 0004, but the same shape recurs with any freshly made CA |
| Agents rejected after regenerating certificates | `api` and `edge` both load certificates at startup. Restart both, and every previously issued agent certificate is now worthless |
| Domain join fails, network looks fine | The member is not resolving DNS through the DC |
| Kerberos fails with nothing useful in the message | Clock skew over five minutes |
| The token vanishes from Windows | It is attached to WSL2 |
| Smart-card logon fails but the certificate looks perfect | The issuing CA is not in `NTAuthCertificates`, or the KDC has no PKINIT certificate — see [04](04-pki-backends.md#strong-certificate-mapping) |
