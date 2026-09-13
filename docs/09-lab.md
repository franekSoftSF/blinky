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

| Machine | Address | Role | What only it can prove |
|---|---|---|---|
| **BY-CACMS** | `172.16.5.11` | Docker host: `api`, `worker`, `postgres`, `edge` | That the backend works when it is not on the same machine as anything else |
| **BY-DC01** | `172.16.5.10` | Samba4 AD DC | That a certificate Blinky issued authenticates against a real KDC — the Phase 2 gate |
| **BY-WIN-CLIENT01** | `172.16.5.51` | Windows client, VMware, with the reader | Smart-card logon as a user actually experiences it, and the agent as a Windows service |
| **BY-LX-Client01** | `172.16.5.150` | Linux client | PKINIT without Windows in the way, and the pcsc-lite transport (patch 0017) |

## Names and addresses

Static, on `172.16.5.0/24`, and in the domain's DNS. The controller registers
itself when it is provisioned; the others do not, each for its own reason:

- **BY-CACMS** is a Docker host and not a domain member, so nothing ever
  registers it. Its name is what every certificate names as a distribution
  point, so a missing record here is a revocation check that cannot be made.
- **Windows and Linux clients** register themselves when they join — but not
  before, and the join needs the controller by address.

So, on the controller, once it is up:

```
sudo bash scripts/lab-dns.sh --add by-cacms 172.16.5.11
```

## The resolver, on every machine

A VMware or cloud image ships a public resolver in netplan, and the per-link
setting beats the global one for anything routed over that link. A perfectly
correct `/etc/systemd/resolved.conf` is then read and ignored: the realm
resolves only by luck, and reverse lookups go to a resolver that will never
answer for RFC 1918 space — so lookups do not fail, they wait, and the symptom
is slowness in things with no visible connection to DNS.

All three machines of the `172.16.5.0/24` build shipped with `8.8.8.8`. On each
of them, before anything else:

```
sudo bash scripts/lab-resolver.sh 172.16.5.10
```

It is safe on the controller too, where it leaves the controller's own resolver
alone and fixes only the per-link setting.

The check at the end separates two failures that look alike and are not: the
realm can resolve perfectly while forwarding to the outside world is dead. The
second one shows up as apt breaking, several steps later, on a machine nobody
associates with DNS.

That writes the A record and the PTR. The reverse half matters more than it
looks: without it, anything that canonicalises a host name waits for a timeout
rather than failing, and the symptom is slowness in things with no obvious
connection to DNS.

## The accounts

```
sudo bash scripts/lab-accounts.sh --user jkowalski --display "Jan Kowalski"
```

Two, and the first is the one that gets skipped.

**A service account that reads the directory.** Blinky resolves a UPN and a SID
out of AD and never writes, and an ordinary domain user can already read what it
needs — Authenticated Users have read on those attributes. So the right account
is a plain one with **no rights added at all**: the easiest account in the world
to ask a directory administrator for, and the easiest to audit. Its password
never expires, because a service account whose password ages out takes the
integration down some weeks later, at a moment nobody connects to a password
policy.

**A cardholder who is not an administrator.** The first live issuance in this
lab went to `Administrator`, because that was the account that existed. It
proved the mechanism and proved nothing about the policy — an administrator is a
member of everything, so a certificate that works for one tells you very little.

The script also sets the **userPrincipalName**, which `samba-tool` does not.
A certificate without a UPN in its subject alternative name is refused for
logon, and by then the missing attribute is three steps behind the error.

Both passwords are generated and written to `/root/blinky-lab-accounts.txt`,
readable by root only. Neither is printed.

The service account's password then has to reach the CMS host once. Put that
one line in a file and hand the file to the installer:

```
sudo bash scripts/install-server.sh --hostname by-cacms.blinky.lab     --directory-host by-dc01.blinky.lab     --directory-base-dn DC=blinky,DC=lab     --directory-bind-dn "CN=svc-blinky-ldap,CN=Users,DC=blinky,DC=lab"     --directory-bind-password-file /root/svc-ldap.password
```

A file rather than an argument, because a password on a command line is visible
in `ps` for as long as the command runs and stays in shell history afterwards.

Better still where it can be arranged: leave the bind DN out entirely and give
the container a keytab, so it binds with Kerberos and no password travels or is
stored at all.

## Order of setup

Each step depends on the one before it, and skipping ahead produces failures
that look like something else.

### 1. blinky — the Docker host

```bash
sudo bash scripts/provision-cms.sh
```

Docker, the repository, the certificates, the secrets, the CA and the stack.
The certificate carries the machine's name **and its address**, because until
the DC is serving the realm the name does not resolve and the address is the
only way in — a name missing from that list surfaces much later as an agent
that will not connect, complaining about trust rather than about a name.

The secrets are generated rather than copied from an example, and `.env` is
written root-only: it holds the database password, the bootstrap token, the
operator token, and the key protecting every escrowed PUK.

Ports the other machines need: **8443** console, **9443** agents. PostgreSQL on
5432 is published for inspection and does not need to leave the host.

Copy `certs/dev-ca.crt` off the machine — every client needs it.

### 2. dc — Samba4

```bash
sudo bash scripts/provision-dc.sh
```

One command, and it refuses to run on a machine that is already a DC —
provisioning over an existing directory produces something that half works and
fails later in ways that point everywhere except at the cause. The realm is
`BLINKY.LAB`; override with `REALM=` and `DOMAIN=`.

**Pick it before the first run.** It ends up inside the directory and inside
every certificate as a UPN suffix, and changing it afterwards means tearing the
domain down and provisioning again — which is what happened here once already,
because the script shipped with a default instead of asking.

The domain administrator's password is generated and written to
`/root/blinky-lab-dc.txt`, readable by root alone, rather than left in a
terminal scrollback nobody clears.

What the script does beyond the provision, and why each one is in it rather
than in a list of things to remember:

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

### Every other machine

```bash
sudo bash scripts/join-lab.sh 172.16.5.10
```

DNS at the DC, clock from the DC, then the join. The first two are checked
before the third is attempted, because a member that resolves the realm through
the house router fails a join with something that reads like a network fault,
and a clock six minutes out fails Kerberos with something that mentions no
clock at all.

### 3. win — the Windows client

A VMware guest, joined to the domain, with the YubiKey passed through to it.

```
Agent__BackendUrl=https://blinky.lab:9443
Agent__Domain=blinky.lab
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

## The ADCS connector on a Windows member server, through a tunnel

HZCS01 (`172.16.2.40`), Windows Server 2022, joined to `ad.digitalworkspace.pl`.
Recorded because the obvious way to try the connector there fails twice before it
works, and neither failure says why.

```bash
dotnet publish src/Blinky.AdcsConnector -c Release -r win-x64 --self-contained true -o publish
scp -r publish administrator@172.16.2.40:C:/Blinky/AdcsConnector
ssh -L 18444:127.0.0.1:8444 administrator@172.16.2.40 "C:\Blinky\AdcsConnector\Blinky.AdcsConnector.exe"
dotnet run --project tools/AdcsProbe -- --connector https://127.0.0.1:18444 \
  --client client.p12 --client-password ... --fingerprint <listener sha256>
```

- **Self-contained**, because the server has no .NET runtime and does not need one.
- **Listen on `127.0.0.1`** and tunnel. No firewall rule, and nothing else on the
  network can reach a connector that is being tried out.
- **Over a key-authenticated SSH session the connector runs as a local account.**
  It can sign with a machine-store agent and it cannot read the directory or
  authenticate to a CA — ADSI says the domain does not exist. Registration checks
  and submissions need the service, as the computer or a managed service account.
- **A PKCS#12 listener loads into the machine key set there**, because DPAPI has no
  user credential in that session; the log says so. See
  [15](15-adcs-connector.md).
- **The CA is `SUBCA\DigitalWorkspace Issuing CA - homelab`** (`172.16.2.16`) —
  the host, not the computer account `SUBCA$`, and the CA's full common name.
  From the SSH session every config string fails with `RPC_S_SERVER_UNAVAILABLE`,
  real or not; from a domain session the CA answers.
- **The enrolment agent is on the computer**: `LocalMachine\My`, SHA-1
  `52D58935B60E92CFE4B6F26FA7B4DAEE3A757A3D`, template
  `BlinkyEnrollmentAgent(Computer)`, key not exportable. So the service runs as
  `LocalSystem`, and Enroll on the smart-card template goes to `HZCS01$`.
- **The service is `BlinkyAdcsConnector`**, installed by the lab's owner, first as
  `LocalSystem` and now as `AD\svc_blinky`. That account holds Enroll on
  `BlinkySmartCardLogon` through a group, read access to the agent's private key,
  and the CA's certificate-management permission. It runs from `C:\Blinky\AdcsConnector`, with `Connector:CaConfig` naming
  `SUBCA` and the agent chosen by fingerprint. To try a new build: stop the
  service, copy `Blinky.AdcsConnector.dll`, start it. The tunnel is then
  `ssh -N -L 18444:127.0.0.1:8444 administrator@172.16.2.40`, with nothing run on
  the far side. `--check BlinkySmartCardLogon --remote-agent` through it ends
  `UNVERIFIED` with `revocation-unavailable` and `template-publication-unknown`.
  Until the certificate-management permission was granted, that was the expected
  answer for this lab, not a fault; with it, only `template-publication-unknown`
  remains.
- **The smart-card template takes ECC and RSA.** `BlinkySmartCardLogon` first sat on
  the default cryptography settings, and a P-256 key was denied with
  `CERTSRV_E_KEY_LENGTH`. It is now a *Key Storage Provider* template with
  `ECDH_P256` and a 256-bit minimum, and both `--key ECCP256` and `--key RSA2048`
  issue. `--check` says so as `template-key-algorithm`, a warning. The test user is
  `AD\BlinkyUser`.
- **`--retrieve <request id>` reads a certificate back**, revoked or not, and prints its
  key, key usage, EKUs, UPN and SID extension. The request id is the end of the ADCS
  serial number: `...00000A` is request 10.
- **`--revoke <serial>` revokes at the CA** through the connector, reason
  `CessationOfOperation` unless `--reason` says otherwise. The first test
  certificate, `47000000097012D4FEBA5C0A0E000000000009`, was revoked this way.
- **Starting it as the local administrator leaves `C:\ProgramData\Blinky`** owned
  by that account. Remove it before starting the service under another identity, or
  that identity may not be allowed to reset its access list and the service stops
  at start.

## A card from the console through ADCS — the plan, not yet run

Written on 2026-09-13, after the probe had issued and revoked through the connector
and before anything below was done. It is the phase 3 gate: the same enrolment
workflow, the same console and the same audit trail, with a Microsoft CA behind them.
Each step says who does it and what shows it worked, and the plan stops at the first
step whose check fails.

**One decision first, and it is the lab owner's.** The stack on BY-CACMS is wired to
the Samba4 domain `blinky.lab` and the built-in CA, and phase 2's gate was reached on
it. Pointing it at ADCS means a second `.env` for `ad.digitalworkspace.pl`: a
different directory, a different CA, and cardholders who do not exist in the other
domain. Either keep a copy of the current `.env` and switch back afterwards, or bring
up a second stack elsewhere. The steps assume the first.

| # | Who | Step | Checked by |
|---|---|---|---|
| 1 | owner | **Revised: the connector dials the API** (docs/15). HZCS01 reaches `by-cacms.blinky.lab:9443`, resolves the name, and trusts the Blinky root; BY-CACMS reaches ADC01 on 636 for the directory | **Done 2026-09-13**: from HZCS01, TCP and TLS 1.3 to 9443 by name with no policy errors after the owner added the DNS record and the Blinky roots; the API answered 401 without a client certificate. ADC01:636 from BY-CACMS not yet checked |
| 2 | owner, then Claude | On HZCS01, `scripts/new-connector-request.ps1 -Out ...csr`; on BY-CACMS, `sudo bash scripts/sign-connector-cert.sh --csr ...`, copied with `scp` and not a clipboard; back on HZCS01, `-Accept ...crt`, and read access to its key for `AD\svc_blinky` | **Done 2026-09-13.** Thumbprint `ED43662A0DC65844965C14989879955525059E14`, SHA-256 `9454FEE459D7188C27A5CFC5F970E9977DA8874751887E1B74243F92E7AEF354`, issuer *Blinky development agent CA* |
| 3 | Claude | The connector's `appsettings.json` on HZCS01: `Connector:Api:Url=https://by-cacms.blinky.lab:9443` and the thumbprint from step 2. No firewall rule and no listener | **Done.** `dialling ... no listener`; 401 until step 5, then *Reached ... again*. The previous configurations are beside it as `appsettings.listen.json` and `appsettings.polls.json` |
| 4 | owner, with `scripts/set-directory.sh` | A directory account for the API and its password in a root-only file on BY-CACMS, then `sudo bash scripts/set-directory.sh --host ADC01.ad.digitalworkspace.pl --base-dn DC=ad,DC=digitalworkspace,DC=pl --bind-dn <account>@ad.digitalworkspace.pl --bind-password-file <file> --ca-file digitalworkspace-chain.pem --netbios AD`. **DNS first, done 2026-09-13:** BY-CACMS resolved `ad.digitalworkspace.pl` to a public wildcard, 46.242.240.119, because BY-DC01 forwarded everything to 8.8.8.8, and ADC01's LDAPS certificate names only `ADC01.ad.digitalworkspace.pl`. The owner set Samba's `dns forwarder = 172.16.2.10 8.8.8.8` - ADC01 answers its own zone, forwards `blinky.lab` back and recurses the rest - and the name now resolves to 172.16.2.10 on BY-DC01, on BY-CACMS and inside the api container, so `--address` is not needed. `scripts/samba-conditional-forwarder.sh`, a per-zone forward through BIND9_DLZ for a trust, was written and not run. The chain is DigitalWorkspace Root CA and Issuing CA, exported from HZCS01's machine store | The script refuses to write anything until TLS verifies; checked by hand first, `Verify return code: 0 (ok)`. Then `POST /api/directory/test` and `/api/directory/test-resolve` for `BlinkyUser` **Done 2026-09-14**, after two corrections: the bind DN was first left as the example `svc-blinky-ldap`, which does not exist, and the API answered every cardholder lookup with 500 and `LdapException: The supplied credential is invalid`. |
| 5 | owner, with a script from Claude | `sudo bash switch-to-adcs.sh` in `~/blinky` - not in the repository, a lab one-off - which keeps `.env.builtin` and sets: `CA_BACKEND=Adcs`, `ADCS_TRANSPORT=ConnectorPolls`, `ADCS_CONNECTOR_CLIENT_FINGERPRINTS` from step 2, `ADCS_TEMPLATE_SMARTCARD_LOGON=BlinkySmartCardLogon`, `ADCS_KEY_ALGORITHM` to match step 7. `docker compose config` first, because the compose keys for ADCS have never been parsed | API and worker start; `/api/system/status` shows the CA reachable and the agent; `GET /api/system/ca/checks` ends `Unverified` with only `template-publication-unknown` | **Partly done.** API and worker recreated; the connector collects calls and the status page answers through it. The registration check has not been read from the console yet. Undo: `sudo cp -p .env.builtin .env && sudo docker compose up -d` **Done.** One defect that only compose showed: the image starts through `/bin/sh -c exec dotnet ...`, sh drops variables whose names are not identifiers, and `Blinky__Adcs__Templates__smartcard-logon` never reached the process - every enrolment was refused with *names no ADCS template*. Compose now starts both services in exec form. |
| 6 | owner | A Windows workstation joined to `ad.digitalworkspace.pl`, not BY-WIN-CLIENT01 (the Samba reference) and not HZCS01 (the connector and the enrolment agent key), with the YubiKey passed through. From a folder holding the agent MSI, Yubico's minidriver MSI and both scripts: `.install-windows-client.ps1 -BootstrapToken <from BY-CACMS .env> -EnableEccLogon` - the Blinky chain, the minidriver (refused unless validly signed by Yubico), the ECC logon policy, the agent and the tray; the domain is taken from the join. Restart before the first logon | The agent enrols its machine certificate and the console lists the machine and the reader **Done 2026-09-14 on VDF001**, agent 0.4.8, then 0.4.9 and 0.4.10 as the enrolment found two defects. Registered first as `VDF001.blinky.lab` because the installer preferred a remembered domain to the join, and could not trust the edge because `/pki/root.crt` answered 404 under ADCS; both fixed. |
| 7 | owner, from the console | Enrol `BlinkyUser` onto the YubiKey, profile `smartcard-logon`, one key algorithm chosen on purpose - RSA 2048 first, because it needs no workstation policy | The job ends installed; the certificate's subject, UPN and SID extension name `BlinkyUser`, not `svc_blinky`; the connector log has one `Signed as enrolment agent for AD\BlinkyUser` with the card's key hash **Done 2026-09-14** with `tools/lab-enrol.ps1` - the console has no enrolment page yet - for the ordinary account `s.frankiewicz` onto YubiKey 5.8.0 serial 39218739, RSA 2048. Two firmware findings on the way: the attestation chains to *Yubico Attestation Root 1* through intermediates the card does not carry, and a PIN verified while opening the card no longer satisfied the new key at signing (6982). Issued: serial `470000000E66720890519367F500000000000E`, `CN=szymon frankiewicz, OU=Users, OU=DIGITALWORKSPACE, DC=ad, DC=digitalworkspace, DC=pl`; the connector logged `Signed as enrolment agent for AD\s.frankiewicz ... asked by API at https://by-cacms.blinky.lab:9443`; the credential was confirmed installed. |
| 8 | owner | Smart-card logon to that workstation as `BlinkyUser` | A session. If not, `certutil -scinfo` on the workstation and the DC's System log for KDC events before anything else **Done 2026-09-14**: `certutil -scinfo` read the certificate, and smart-card logon to VDF001 over RDP succeeded. The first attempt found no card at the logon screen, reached through a remote session - the logon screen of a remote session sees the cards redirected from the client, not the ones attached to the VM. |
| 9 | owner, from the console | Suspend the credential | The CA lists it *revoked, certificate hold*, by `AD\svc_blinky`; Blinky's `audit_events` has `credential.revoked` naming the operator; after the next CRL the logon from step 8 fails Not yet run. |

What this does not cover, and is not pretending to: lifting the suspension at the CA
(Blinky does not un-revoke), a second CA, CES, and certificate manager restrictions on
`svc_blinky`, whose grant is CA-wide in this lab.

What has to be true on the domain side before step 8, which a Microsoft enterprise CA
usually arranges and nobody here has checked: the issuing CA in `NTAuthCertificates`,
a *Kerberos Authentication* certificate on ADC01, and a CRL both ADC01 and the
workstation can fetch. `certutil -dcinfo verify` on ADC01 answers the first two.

## The connector dialling a probe instead of the API

Before an API with the queue is deployed anywhere, `AdcsProbe --queue` plays the API's
half on the workstation running it, and the connector on HZCS01 reaches it through a
reverse tunnel. Used on 2026-09-13 to run the polling transport against the lab CA.

```bash
ssh -N -R 19443:127.0.0.1:19443 administrator@172.16.2.40
dotnet run --project tools/AdcsProbe -- --queue https://127.0.0.1:19443 --queue-certificate server.pfx --queue-password ... --connector-fingerprint <sha256 of the connector's client certificate> --check BlinkySmartCardLogon --remote-agent
```

- The connector's `appsettings.json` needs `Connector:Api:Url=https://127.0.0.1:19443`,
  `Connector:Api:ServerFingerprint` of the probe's `server.pfx`, and a client
  certificate; the lab used `listener.pfx`. Both configurations are kept beside it on
  HZCS01, `appsettings.listen.json` and `appsettings.polls.json`, and the listening one is
  in place.
- Start the tunnel before the probe. A connector that failed a few polls waits at most
  15 seconds before the next, under the queue's 20-second pickup deadline.
- Each probe run is a new queue, so the connector logs a failed poll or two between runs.
  That is the probe exiting, not a fault.

## Running the PKCS#11 tests

They are skipped where no module is installed, which includes CI on
`windows-latest`, and the skip says so rather than the tests passing quietly.

The module is found from `BLINKY_PKCS11_MODULE`, or from the usual places
SoftHSM2 installs itself. On Debian or Ubuntu:

```bash
sudo apt-get install -y softhsm2 && dotnet test tests/Blinky.UnitTests/Blinky.UnitTests.csproj --filter Pkcs11
```

**Name the project, not the solution.** `dotnet test` with no argument resolves
`Blinky.slnx`, which holds the WPF tray and the DCOM connector, and on Linux
that stops at `NETSDK1100` before a single test runs.

**And do not add `--no-build`.** On the 10.0.401 SDK it makes `dotnet test`
print nothing at all and exit zero, having run no tests — which reads exactly
like a green suite. Measured here, both on Linux; `dotnet vstest` against the
built assembly reports normally, if a run without a build is what you want.

The fixture makes its own token in a temporary directory and points the module
at it, so nothing is written to a store anybody is using. It provisions through
the same code `tools/SecretsTool` runs, which is the point: provisioning that
only the tests can do would prove nothing about the procedure an operator
follows.

Where there is no Linux to hand, a container works and needs nothing installed:

```bash
docker run --rm -v "$PWD":/src -w /src mcr.microsoft.com/dotnet/sdk:10.0 bash -c "apt-get update -qq && apt-get install -y -qq softhsm2 && dotnet test tests/Blinky.UnitTests/Blinky.UnitTests.csproj --filter Pkcs11"
```

Run on BY-CACMS on 2026-09-12: eleven passed, nothing skipped.

Two things to expect if you run the **whole** suite in that container rather
than the filter. `UserPromptTests` fails twice, because the agent's tray talks
to its service over a named pipe and that pair is a Windows arrangement; both
failed identically on `b9b2285`, before any of this existed, so they are the
platform and not a regression. And the nine PKCS#11 tests only run if the
module installed — a suite reporting them as skipped is telling you `apt-get`
did nothing, not that the code is fine.
