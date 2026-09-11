# 15 — Blinky.AdcsConnector

Patch 0032. A Windows service that sits beside a Microsoft CA and hands it
certificate requests over DCOM, because `ICertRequest3` cannot be called from a
Linux container and a product that pretends otherwise demos well and does not
deploy. [04](04-pki-backends.md) chooses between this and CES/CEP; this
document is the connector itself and the list of things that have to exist
elsewhere before it is of any use.

## What it is, and what it deliberately is not

It is a transport. It takes bytes that are already a complete certificate
request, calls `ICertRequest3::Submit`, and returns what the CA said.

It is **not** a certificate authority, and it holds no enrolment agent key.
Every decision about what a certificate should say — the subject, the template,
the SID extension, and above all the enrolment agent's signature over the
cardholder's PKCS#10 — is made on the other side of this wire, in
`AdcsCertificateAuthority`, and is shared with the CES transport. That is what
makes the roadmap's promise true: *switching transports is one config value and
no other change*. A decision made here would be a decision CES does not make,
and the two would drift apart within a release.

The consequences are worth stating plainly, because they are the reason the
connector is small:

- The connector references `Blinky.Contracts` and **not** `Blinky.Pki`. It
  cannot see `ICertificateAuthority` and cannot grow half an implementation of
  one.
- The enrolment agent's private key stays behind `IKeyProvider` in the
  container, where [06](06-security.md) can reason about it. A key on the CA
  server would be a second copy of the most powerful credential in the system,
  on a machine Blinky does not own.
- The connector never sees a PIN, a PUK or a management key. Nothing it logs
  can leak one, and there is no redaction rule here because there is nothing to
  redact.

## The shape

```
Blinky.Api / Blinky.Worker            (Linux container)
        │  builds the CMC, signs it with the EA certificate
        │
        │  HTTPS, mutual TLS, JSON        ← this document
        ▼
Blinky.AdcsConnector                  (Windows, beside the CA)
        │  ICertRequest3 / ICertAdmin2, in process
        ▼
    ADCS
```

## The wire

`Blinky.Contracts/AdcsTransportContracts.cs`, versioned by
`AdcsTransport.SchemaVersion` — **separately from `Protocol.SchemaVersion`**.
The two ends upgrade on different change windows: the container upgrades when
Blinky is upgraded, the connector when whoever owns the CA server opens a
maintenance window. One number for both would mean a container upgrade
silently demanding work on a machine nobody here can reach. A version the
connector does not speak is refused with that sentence, not guessed at.

Enums cross this wire as **names** — `"Cmc"`, `"Denied"` — unlike the job
contracts, and the converter is on the type rather than in either host's
serialiser options so that both ends agree without being configured to. The far
end is a service on somebody else's Windows server, and whoever diagnoses it
will be reading the body in a terminal.

| Method | Path | Answers |
|---|---|---|
| `GET` | `/connector/health` | That the service is up. No CA call — a healthy connector in front of a stopped CA is a different fault from a connector that failed to start |
| `GET` | `/connector/describe` | The CA's config string, its name, its chain, whether this account may *manage* certificates, and its template list. What 0033 checks at registration |
| `POST` | `/connector/submit` | A disposition, and a certificate with its chain when the disposition is issued |
| `POST` | `/connector/retrieve` | The same, for a request a certificate manager has since approved |
| `POST` | `/connector/revoke` | Whether the revocation was accepted |

Two things about the answers are on purpose. The **CA's own disposition
message is passed through verbatim** — "The request subject name is invalid or
too long" is worth more to whoever reads the failure than anything this code
could write instead. And `UnderSubmission` is neither success nor failure: the
request is waiting for a person to approve it, possibly until tomorrow, and
folding it into a boolean would lose a certificate that is on its way.

The chain comes back from the CA in the same call that returns the certificate.
Rebuilding it in the container would mean maintaining the customer's CA
hierarchy in a Linux trust store, to learn something the CA already knows.

## How it decides who may call

Mutual TLS, and the authorisation is a **list of SHA-256 fingerprints** —
`Connector:AllowedClientThumbprints`. Not an issuer, not a subject name.

Trusting an issuer would mean that every certificate that issuer ever signs can
ask this connector to enrol on a stranger's behalf, and the whole point of the
enrolment agent model is that asking on somebody else's behalf is controlled. A
fingerprint cannot be widened by somebody else's decision. The cost is that
rotating the API's client certificate is a configuration change on the CA
server, which is why the setting is a list: the new fingerprint is added before
the old one is removed.

Four consequences, each of which is in the code for a reason:

- **The TLS handshake accepts any client certificate.** The decision is made in
  the application so that a refusal is a logged 403 naming the fingerprint that
  was presented, rather than a TLS alert that tells the person diagnosing it
  nothing. The fingerprint check is stricter than chain validation, not a
  relaxation of it.
- **Validity dates are checked in the gate.** Nothing else is looking at them
  once the handshake has been told to accept anything, and an expired client
  certificate still named in the file would otherwise keep working for years.
- **An empty allowlist refuses to start.** It is not "allow everybody". A
  service that starts in that state is a DCOM bridge to a Microsoft CA taking
  enrolment requests from anybody who can reach the port, and it will be found
  in that state.
- **SHA-256, not `X509Certificate2.Thumbprint`**, which is SHA-1. That property
  is the reason SHA-1 fingerprints are still pasted into configuration files in
  2026. Both are accepted when locating the connector's *own* certificate in
  the machine store, because which one Windows prints depends on the version.

`Connector:AllowedTemplates` is defence in depth and nothing more — ADCS
enforces template permissions itself and is the authority. It exists so that a
connector installed for smart-card logon cannot be talked into requesting a
subordinate CA certificate if the service account turns out to be
over-granted, which is a thing that happens.

## Running it

The service account matters. A connector running as `LocalSystem` enrols as the
CA's machine account, which is not an identity anybody can grant *Enroll* to on
a template in a way that means what they intended. It runs as a domain service
account, and that account needs:

- *Request Certificates* on the CA, and *Enroll* on the target template;
- *Issue and Manage Certificates* **only if revocation through this connector
  is wanted** — a separate grant, routinely missing, and `describe` reports its
  absence as `AdminAvailable: false` so the console can say revocation is
  unavailable instead of offering a button that fails;
- read access to the private key of the connector's own TLS certificate. This
  is the most common reason a first start fails, and the error says so.

State lives under `%ProgramData%\Blinky\AdcsConnector`, created with
inheritance switched off for the reason `AgentPaths` records: a directory
created there inherits `BUILTIN\Users:(RX)`, and this one holds the log of who
asked the connector to enrol whom. `connector.json` in that directory overrides
`appsettings.json`, so the deployment's settings are not in `%ProgramFiles%`
where every local user can read them.

Calls into COM are **serialised**, one at a time. `ICertRequest3` is not
documented as safe to call concurrently from one process, the CA behind it is a
single database, and the load is one certificate per enrolment ceremony — a
person, plugging in a token. The deadline bounds the caller's wait and not the
call: there is no way to abort a DCOM call in flight, so a timed-out submission
keeps its thread inside DCOM *and keeps the lock*, and callers behind it are
told the connector is busy. Releasing the lock on the timeout would start a
second call into a CA that has not finished the first.

### Configuration

| Key | What it is |
|---|---|
| `Connector:ListenUrl` | One address, HTTPS only. There is no HTTP fallback |
| `Connector:CaConfig` | `HOST\CA common name`. Empty asks `ICertConfig` for the active local CA, which is right on a box with one CA and ambiguous on a box with two |
| `Connector:ServerCertificate:Thumbprint` | In `LocalMachine\My`. The right answer on a domain-joined CA, where Windows renews it and nobody has to remember a file |
| `Connector:ServerCertificate:Path` / `:Password` | A PKCS#12 instead. For a lab, and for a CA that is not itself in the PKI it runs |
| `Connector:AllowedClientThumbprints` | SHA-256, any separators. Startup fails when empty |
| `Connector:AllowedTemplates` | Empty means no restriction |
| `Connector:RequestTimeoutSeconds` | Default 60, floor 5 |

## What has to exist in the main tree

The connector compiles, starts, refuses unauthorised callers and answers all
five endpoints. Nothing in Blinky calls it yet. This is what is missing, in the
order it has to arrive.

### 1. `Blinky.Pki/Adcs/` — patch 0030, the prerequisite

Nothing else on this list is worth doing first.

- **`IAdcsTransport`** — the interface with two implementations behind it, one
  per transport. Shape it from the contract in
  `Blinky.Contracts/AdcsTransportContracts.cs`, which was written for it:
  describe, submit, retrieve, revoke.
- **`AdcsCertificateAuthority : ICertificateAuthority`** — the one place that
  builds a request and reads an answer. `DescribeAsync` maps the connector's
  `describe` onto `CaCapabilities` with `PublishesCrl: false`,
  `SupportsSuppliedSubject: false` and `SupportsRevocation` taken from
  `AdminAvailable`.
- **CMC construction with an enrolment agent signature.** The hard half, and
  the half 0023a needs a compatible answer to for the built-in CA. Whoever
  writes the first should write the request format so the second can use it.
- **The enrolment agent's key behind `IKeyProvider`** — `Blinky.Secrets`, a
  third purpose alongside the management-key master and the PUK KEK. It is the
  most powerful credential in the system and it does not belong in a file.
- **`ConnectorAdcsTransport : IAdcsTransport`** — the HTTP client for this
  document's wire. Client certificate from configuration, the connector's
  server certificate pinned or trusted explicitly, and a refusal when
  `AdcsTransport.IsSupported` says the far end speaks a version this build
  does not. Targets `net10.0` and lives in the container, so it is unit
  testable without a CA.

### 2. Choosing a backend at all — today it is hard-wired

`Blinky.Api/Program.cs:35` and `Blinky.Worker/Program.cs:54` both register
`BuiltInCaFactory.LoadFromDirectory` as *the* `ICertificateAuthority`. There is
no seam. Both need a resolver that reads `CaInstance.Backend` and
`CaInstance.Configuration` and produces the right implementation, and
`CredentialIssuanceService` and `MaintenanceRunner` need to ask it for the
instance a profile names rather than taking a singleton.

Until that exists, an ADCS instance in the database changes nothing.

### 3. `CaInstance` has a jsonb column and no shape

`Configuration` is `"{}"`. The ADCS shape needs writing down as a record and
validating on save: connector URL, client certificate, expected server
fingerprint, CA config string, template name, and whether revocation is
permitted. A jsonb column that different code parses differently is a schema
nobody validates.

### 4. `CaInstance` has no CRUD, which the repository's own rule forbids

[CLAUDE.md](../CLAUDE.md): *a new model arrives with full CRUD*. `CaInstance`
predates that rule and never got one — there is no endpoint and no console
page, so a CA instance can only be created by writing SQL. An ADCS backend is
unusable without it, since registering one is the entire operator-facing story
of this phase. Listable, readable, creatable, editable, deletable, in the same
change that makes the backend selectable.

### 5. Registration checks — patch 0033

`describe` was shaped to answer these before the first enrolment rather than
during it: the EA certificate missing or expired, the service account without
*Enroll*, the template supplying the subject in the request (which breaks the
SID extension — [04](04-pki-backends.md)), and revocation wanted without
*Issue and Manage Certificates*. Each refusal names which one it was.

One caveat for whoever writes it: `Templates` is `null` when the connector
could not establish the list, and that is **not** the same as an empty list.
Reading null as "the CA has no templates" would refuse a correct registration.

### 6. Deployment

- **`.env.example` and `docker-compose.yml`** — the connector URL and the
  client certificate the container presents. Neither exists today; there is not
  one `ADCS` key in either file.
- **A client certificate for the API.** Not an agent certificate: the agent CA
  issues workstation identities, and an agent that could impersonate the API to
  the connector would be able to enrol on anybody's behalf. A separate pair,
  and its fingerprint is what goes into `AllowedClientThumbprints`.
- **`installer/`** — holds `agent.wxs` and nothing else. The connector needs
  its own: service registration under a named account, the `%ProgramData%`
  directory, the firewall rule for `ListenUrl`, and the private-key grant that
  is otherwise the first thing to go wrong.
- **`docs/09-lab.md`** — a Windows AD + ADCS lab, an enrolment agent template
  and a copy of *Smartcard User*. The phase gate is the same enrolment against
  ADCS that already works against the built-in CA, and none of it can be
  checked without one.

### 7. `docs/STATUS.md`, `docs/status.json`, `docs/07-roadmap.md`

Both status files together, including `status.updated`, and 0032 does not
become `done` until an enrolment has gone through a real CA. The transport
existing is not the definition of done.

## What has actually been exercised

On a Windows bench with **no Certification Authority installed**, which is
enough to prove everything except the DCOM calls themselves. Two self-signed
PKCS#12 files, one for the listener and one for the caller:

```
dotnet run --project src/Blinky.AdcsConnector -- \
  --Connector:ListenUrl=https://127.0.0.1:18444 \
  --Connector:ServerCertificate:Path=server.pfx \
  --Connector:ServerCertificate:Password=... \
  --Connector:AllowedClientThumbprints:0=<sha256 of the client certificate>
```

| Asked | Answered |
|---|---|
| `health`, with the listed client certificate | 200, and the connector's version |
| `health`, with a client certificate that is not listed | 403, *the client certificate is not one this connector was told to accept* |
| `submit`, schema 9 | 400, *this connector speaks schema 1 to 1 and was sent 9* |
| `submit`, a request that is not base64 | 400, *the request is not base64* |
| `submit`, a body the binder cannot read | 400, in the contract's own shape rather than the framework's |
| `revoke`, a serial number that is not hex | 400, *a serial number is hex digits and nothing else* |
| `describe` and `submit`, no CA on the machine | 502, *no certification authority is active on this machine and none was named*, with `0x80070002` |

That last row cost two defects, both of which would have survived into the lab:

1. **Every `catch` in the COM layer was dead code.** Late binding wraps what the
   call throws in a `TargetInvocationException`, so nothing matched, and a
   describe answered 500 with a stack trace instead of the 502 and the sentence
   it was written to answer with. `Invoke` now unwraps.
2. **`catch (COMException)` was the wrong net even after unwrapping.** .NET maps
   some HRESULTs to their own types first: `CCertConfig::GetConfig` on a machine
   with no CA arrives as a `FileNotFoundException` carrying `0x80070002`, and
   access denied arrives as `UnauthorizedAccessException` — which is exactly the
   exception the `AdminAvailable` probe is looking for.

Both were found by starting the thing and asking it a question. Neither would
have been found by a unit test, because neither is reachable without COM.

## Unverified, and named as such

Nothing here has met a Microsoft CA. It builds, it starts, it refuses what it
should refuse, and its access control and parsing are under test. That is all
that is claimed.

Three specific things to check first against a lab CA, because they are the
places where the documentation is thin enough that this code is reasoning from
the shape of the API rather than from behaviour anybody observed:

1. **The revocation date.** An unnamed time is sent as a `DATE` of zero so the
   CA stamps its own clock, which avoids the question. A *named* time is sent
   as UTC, and whether `ICertAdmin2::RevokeCertificate` reads an unqualified
   `DATE` as UTC or as the CA's local time has not been established here.
2. **The template list.** Read from
   `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA>\Templates`
   as alternating OID and name, because no `ICertAdmin` call lists them. Best
   effort, null on any failure.
3. **`AdminAvailable`.** Probed by asking the CA to un-revoke serial `00`,
   which cannot exist. It reaches the permission check and fails there, which
   is exactly the question being asked, without touching a real certificate.
   Access denied is "no"; anything else means the call got as far as the
   database. Whether every ADCS version answers that way is worth watching —
   findings go to [08](08-hardware-notes.md).
