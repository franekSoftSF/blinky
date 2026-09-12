# 15 — Blinky.AdcsConnector

Patch 0032. A Windows service that sits beside a Microsoft CA and hands it
certificate requests over DCOM, because `ICertRequest3` cannot be called from a
Linux container and a product that pretends otherwise demos well and does not
deploy. [04](04-pki-backends.md) chooses between this and CES/CEP; this
document is the connector itself and the list of things that have to exist
elsewhere before it is of any use.

## What it is, and what it deliberately is not

It is a transport, and it is where the enrolment agent's key lives. It signs a
`PKIData` it did not build, submits the result through `ICertRequest3::Submit`,
and returns what the CA said.

It is **not** a certificate authority, and it decides nothing about a
certificate. Who it is for, against which template, and what goes into the
request are chosen on the other side of this wire, in `AdcsCertificateAuthority`,
and shared with the CES transport. That is what keeps the roadmap's promise true:
*switching transports is one config value and no other change*. A decision made
here would be a decision CES does not make, and the two would drift apart within
a release.

**The enrolment agent's key used to be on the other side too, and moved here on
purpose.** The first version of this document kept it in the container and
called the connector a transport and nothing more. That lost on the one thing
that matters most for this key, which is how it is held:

- **In the integration account's store the key can be non-exportable**, or live
  in a TPM, and never exist as a file. In the container the only tier was a
  PKCS#12 exported from a template that allows export, with a password beside
  it — exactly what [06](06-security.md) calls not production-ready.
- **The CA server is already the most trusted machine here.** Whoever holds it
  issues what they like with or without an agent, so the key adds almost nothing
  for an attacker there, and a great deal for one in a container.
- **Windows renews it.** Autoenrollment keeps an agent certificate current on a
  domain server; in a container, renewal is a person remembering.

So the decision stayed where it was and the key moved. The container still
builds the `PKIData` with `CmcRequest`. It sends that to `/connector/sign`, which
refuses anything that is not exactly one enrolment, signs, and logs what it
vouched for. CES deployments have no Blinky service on the Windows side and keep
the key in the container, behind the same `IEnrolmentAgentKeyStore`.

The consequences, stated plainly:

- The connector references `Blinky.Contracts` and **not** `Blinky.Pki`. It
  cannot see `ICertificateAuthority` and cannot grow half an implementation of
  one. The certificate rules it shares with `FileEnrolmentAgentKeyStore` are
  duplicated, and a test runs the same certificates through both.
- **The client certificate the container presents is now worth as much as the
  enrolment agent key**, because holding it buys that key's signature. It is the
  cost of the move, and the reason signing is restricted as it is below.
- The connector never sees a PIN, a PUK or a management key. Nothing it logs
  can leak one.

## The shape

```
Blinky.Api                             (Linux container)
        │  chooses cardholder and template, builds PKIData
        │
        │  HTTPS, mutual TLS, JSON         ← this document
        │    /connector/sign    PKIData in, CMC out
        │    /connector/submit  CMC in, certificate out
        ▼
Blinky.AdcsConnector                   (Windows, beside the CA)
        │  refuses anything but one enrolment, signs as the agent
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
| `GET` | `/connector/describe` | The CA's config string, its name, its chain, whether this account may *manage* certificates, its template list, and the enrolment agent it holds — with whether that key may be exported, read off the key. What 0033 checks at registration |
| `POST` | `/connector/sign` | A CMS signature over a `PKIData`, as the enrolment agent. 400 with the reason for anything that is not one enrolment; 409 when this connector holds no agent |
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

### What the enrolment agent will sign

A client certificate buys a signature, so the question the connector answers is
never "sign these bytes". `PkiDataInspection` parses the content before the key is
touched and refuses, each with its own sentence:

| Refused | Because |
|---|---|
| Anything in `controlSequence` | A control can be `id-cmc-revokeRequest`, which is a signed revocation |
| No request, or more than one | One agent signature is one enrolment |
| A request tagged `[1]` or `[2]` | CRMF and other formats are not what a card produces, and signing a format this code does not read is signing something unread |
| Anything in `cmsSequence` | Nested signed content would reach the CA under this signature without having been read here |
| Anything in `otherMsgSequence`, or bytes after the `PKIData` | Nothing Blinky builds puts anything there |
| A PKCS#10 whose own signature does not verify | Its proof of possession is broken, and the agent should not be on record as having vouched for it |

Blinky's own `CmcRequest` produces none of the refused shapes, so refusing all of
them costs nothing.

**Every signature is logged on the CA server** with the request's subject, the
SHA-256 of the key it vouched for, and the fingerprint of the client certificate
that asked. The subject a card writes is not what ADCS issues — the template
builds that from the directory — so the key hash is the field to match against
the issued certificate afterwards. This record did not exist while the key lived
in the container.

The agent certificate's dates are checked again at every signature, not only at
start. A service that runs for a year outlives the certificate it started with,
and ADCS would refuse the CMC with a message about the signer rather than the
date.

`Connector:AllowedTemplates` is defence in depth and nothing more — ADCS
enforces template permissions itself and is the authority. It exists so that a
connector installed for smart-card logon cannot be talked into requesting a
subordinate CA certificate if the service account turns out to be
over-granted, which is a thing that happens.

## Running it

The account the service runs as is the requester the CA sees. **This paragraph used
to say `LocalSystem` was wrong**, because it enrols as the machine account; the lab
showed that a computer-bound enrolment agent with Enroll granted to the computer is
a coherent arrangement, and section 7 now has both. Whichever it is — a group managed
service account or the computer — it needs:

- *Request Certificates* on the CA, and *Enroll* on the target template;
- *Enroll* on the *Enrollment Agent* template, and an enrolment agent
  certificate issued to it, in its own personal store;
- *Issue and Manage Certificates* **only if revocation through this connector
  is wanted** — a separate grant, routinely missing, and `describe` reports its
  absence as `AdminAvailable: false` so the console can say revocation is
  unavailable instead of offering a button that fails;
- read access to the private key of the connector's own TLS certificate. This
  is the most common reason a first start fails, and the error says so.

What this account is, and why it has to be designed rather than created, is
recorded as work still to do below.

**The enrolment agent key, on that account.** Enrol the integration account for
the agent certificate *as that account*, so the key is generated in its store and
never exported at all; if it has to be imported, import it without marking the
key exportable. `describe` reports what the key's own policy says, and the
container treats an exportable key as not production-ready. Two traps:

- **Whether a key may be exported is decided at import, not inherited from the
  file.** Measured: the same PKCS#12 loaded twice gave one exportable key and one
  that was not, depending only on the import flag. "It was exported from
  somewhere" says nothing about the key now on the server.
- **Strong private key protection must be off.** It asks for consent in a window,
  a service in session 0 cannot draw one, and the connector signs silently so
  that this fails with a message instead of hanging.

`CurrentUser` is the integration account's own store, loaded by the service
control manager when it starts the service — not the store of whoever installed
it. That is the usual reason a certificate visible in `certmgr.msc` is "not found".

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
| `Connector:EnrolmentAgent:Thumbprint` | SHA-1 or SHA-256 of the agent certificate. Unset means this connector signs nothing and `/connector/sign` answers 409 |
| `Connector:EnrolmentAgent:StoreLocation` | `CurrentUser` by default — the integration account's store — or `LocalMachine`, where the key's ACL then has to name the account |
| `Connector:EnrolmentAgent:Path` / `:Password` / `:AllowFileKey` | A PKCS#12 instead, refused without `AllowFileKey`. For a laboratory |

An agent that is configured and unusable — expired, missing *Certificate Request
Agent*, or with a key this account cannot reach — stops the service at start,
in front of whoever installed it, rather than at somebody's enrolment.

## What has to exist in the main tree

Both ends of the wire now exist and talk to each other: a signed CMC travels from
`AdcsCertificateAuthority` through `ConnectorAdcsTransport` into
`ICertRequest3::Submit`. **The API can now be pointed at it with one
setting, and no Microsoft CA has seen a request.** What is left is the database,
the console, an account and a CA, in the order they have to arrive.

### 1. `Blinky.Pki/Adcs/` — patch 0030. **A lab CA has issued from it**

- **`IAdcsTransport`** — describe, submit, retrieve, revoke, in the wire
  contract's own vocabulary rather than a translated one. A translating layer is
  where the two transports would stop behaving identically.
- **`AdcsCertificateAuthority : ICertificateAuthority`** — the one place that
  builds a request and reads an answer, written once for both transports.
  `PublishesCrl` is false, `SupportsSuppliedSubject` is false because a template
  that takes the subject from the request emits no SID extension, and
  `SupportsRevocation` follows what the CA said about *Issue and Manage
  Certificates*. A disposition of `UnderSubmission` raises its own
  `IssuancePendingException` carrying the request id: it is neither a success nor
  a refusal, and folding it into either would lose a certificate that is on its
  way.
- **`CmcRequest`** — the CMC full PKI request, hand-encoded, because .NET has no
  CMC type and the alternative is `certenroll`, which is COM, which is the thing
  the container cannot do. The template is *not* in the CMC: it travels in the
  attribute string, which both `ICertRequest3` and CES already accept, and two
  places to change one name is one place too many.
- **`IEnrolmentAgentKeyStore`** — a sibling of `ICaKeyStore`, not a third
  `KeyPurpose` behind `IKeyProvider`, for the reason this document got wrong
  before 0025a landed and the interface could be read. `IKeyProvider` has exactly
  one operation, an HMAC, because both secrets it was built for are KDF roots; an
  enrolment agent signature is a CMS `SignerInfo`. Its one operation is
  asynchronous, because the key need not be in this process. Two implementations:
  - `ConnectorEnrolmentAgentKeyStore`, for any deployment whose transport is the
    connector — the key on the Windows server, asked for a signature over the
    wire, and custody reported from what the key itself says about export.
  - `FileEnrolmentAgentKeyStore`, for CES, where there is no Blinky service on
    the Windows side to hold a key. Refused without `Blinky:Adcs:AllowFileKeys`.

  Both refuse a certificate ADCS would refuse — out of date, or no *Certificate
  Request Agent* — and [06](06-security.md) ranks this key second in the custody
  list.

What remains of 0030 is the part that needs a CA: the definition of done is a CMC
a lab ADCS accepts, and there is no lab ADCS. The encoding is asserted against
RFC 5272 in `AdcsEnrolmentAgentTests` — four sequences, the `[0]` implicit tag,
and the cardholder's PKCS#10 byte for byte inside the agent's signature — which
proves it is the structure intended, not that a CA agrees.

### 1a. The other half of the transport — patch 0032's remainder. **Written**

`ConnectorAdcsTransport : IAdcsTransport, IRemoteEnrolmentAgent` in
`Blinky.Pki/Adcs`, plus `tools/AdcsProbe` to drive it. The second interface is
what `ConnectorEnrolmentAgentKeyStore` talks to, and it is separate from the first
because CES has no equivalent: nothing on the far side of a CES call can hold a
key for Blinky.

**There is no "accept any server certificate" option**, unlike `BackendClient`
where one exists for a single-machine bench. A CMC signed by the enrolment agent
is worth intercepting: whoever has one can submit it to the real CA and collect a
certificate in the cardholder's name. So the transport refuses to be constructed
without either a pinned SHA-256 fingerprint or a trust anchor — and refuses a
40-digit value in the fingerprint setting, because that is the SHA-1 thumbprint
from the wrong field of the certificate dialog and accepting it would mean
pinning nothing.

A fingerprint is the preferred form and is symmetric with how the connector
authorises this client. The connector's certificate is routinely self-signed on a
CA server that is not in the PKI it runs, and pinning one certificate is a
stronger statement than chaining to a CA that signs many things.

Each failure a deployment actually produces gets its own sentence, because from
the API they look identical: an unreachable port, a fingerprint that does not
match, a client certificate the connector was not told about, a connector nobody
upgraded, a proxy answering in HTML instead of the connector, and a timeout —
which arrives as the same exception type as a shutdown, and is how "the CA is not
answering" gets logged as "the request was cancelled".

`tools/AdcsProbe` is read-only by default, like the PIV probes. It prints what
`describe` said, including the agent the connector holds and whether its key may
be exported; `--submit` asks a real CA for a real certificate on behalf of a real
person and is behind a flag for that reason. `--remote-agent` has the connector
sign, `--agent` signs with a file here.

### 2. Choosing a backend — **one configuration value, not yet a database row**

`Blinky:Ca:Backend` in the API and the worker: `BuiltIn`, which is what an
unset value means and what every earlier deployment was, or `Adcs`. Anything
else stops the process at start with a sentence rather than falling back to the
built-in CA, because a typo that issued from the wrong authority would first be
noticed as a workstation that does not trust the certificate. A digit is refused
too: `Enum.TryParse` reads "1" as `Adcs`.

**In the API**, `Adcs` builds an `AdcsCertificateAuthority` from
`AdcsInstanceOptions`, and nothing downstream of the registration knows which it
got. What can be checked locally is checked at start — the transport name, an
absolute https URL, the client certificate, the pin. **The enrolment agent is not
opened until the first enrolment**: the connector lives on a server with its own
maintenance windows, and an API that will not start while that server reboots is
an outage nobody here caused. A connector that was down is asked again at the next
enrolment rather than remembered as down; an agent that opened is kept, and dropped
if its certificate expires while kept.

`/api/system/status` stopped assuming the CA answers. It used to call
`DescribeAsync` bare, which for a built-in CA cannot fail and for a Microsoft CA
is a network call — so the status page would have returned 500 on exactly the day
the page mattered. It now reports `reachable` and `problem`, and names the
transport and the enrolment agent. Additive fields; nothing the console reads
changed name.

**In the worker**, `Adcs` means it does nothing for the CA, and that is a
decision rather than something unfinished left switched on. `MaintenanceRunner`
replays every revocation into the CA before building a list, which is right for a
CA whose list lives in memory and would, against ADCS, re-revoke every revoked
certificate at the CA every cycle and then fail for want of a list to write. The
CA publishes its own. Revocation through ADCS is 0034 and happens when Blinky
revokes, not on a timer.

The same change found a defect that had nothing to do with ADCS: the scheduler
that creates the revocation-list job was registered whenever the worker had a
database, and the runner only when it had a CA directory. A worker without one
wrote a job every period that nothing would ever pick up, and each expired in the
console as a failure. They are now registered together.

**What is still missing** is the half this was meant to be: the resolver that reads
`CaInstance.Backend` and `CaInstance.Configuration` per profile. Profiles still
live in code and name no CA instance, so a template is mapped per instance and
profile in `Blinky:Adcs:Templates`, and a deployment has one CA. That is 0022's
open half, and it is where this configuration moves when profiles become rows.

### 3. `CaInstance.Configuration` — **the shape exists, the column does not use it**

`AdcsInstanceOptions` in `Blinky.Pki/Adcs` is the shape: name, transport,
connector URL, client certificate and its password *file*, the server fingerprint
or anchor, the CA config string, where the enrolment agent lives, the template map,
and whether revocation is permitted. Nothing in it is key material, and that is
the property to keep when it becomes a jsonb column, because a column holding a
PKCS#12 password would put that password in every backup of the database.

The column is still `"{}"`, nothing validates it on save, and nothing reads it.

| Setting | What it is |
|---|---|
| `Blinky:Ca:Backend` | `BuiltIn` or `Adcs`. Unset is `BuiltIn` |
| `Blinky:Adcs:Name` | What the console and the logs call the CA |
| `Blinky:Adcs:Transport` | `Connector`. `Ces` is refused by name until 0031 exists |
| `Blinky:Adcs:Connector:Url` | Absolute https |
| `Blinky:Adcs:Connector:ClientCertificatePath` / `:ClientCertificatePasswordFile` | The certificate that buys the agent's signature. The file wins over `:ClientCertificatePassword` |
| `Blinky:Adcs:Connector:ServerFingerprint` or `:ServerCertificateAuthorityPath` | One of the two is required |
| `Blinky:Adcs:Connector:CaConfig` | `HOSTCA name`, when the connector's default is not the CA meant |
| `Blinky:Adcs:EnrolmentAgent:Location` | `Connector`, or `File` with `:Path`, `:PasswordFile` and `:AllowFileKeys` |
| `Blinky:Adcs:Templates:<profile>` | The ADCS template for that profile |
| `Blinky:Adcs:AllowRevocation` | Default true |

### 4. `CaInstance` has no CRUD, which the repository's own rule forbids

[CLAUDE.md](../CLAUDE.md): *a new model arrives with full CRUD*. `CaInstance`
predates that rule and never got one — there is no endpoint and no console
page, so a CA instance can only be created by writing SQL. An ADCS backend is
unusable without it, since registering one is the entire operator-facing story
of this phase. Listable, readable, creatable, editable, deletable, in the same
change that makes the backend selectable.

### 5. Registration checks — patch 0033. **Written, run against no forest**

`AdcsRegistration` in `Blinky.Pki/Adcs`, reachable as `GET /api/system/ca/checks`
and `tools/AdcsProbe --check <template>`. It asks the CA, reads each mapped
template out of the directory and opens the enrolment agent, and returns findings
with a stable code and a sentence.

**Everything the template can get wrong is on the template object**, so the
connector reads that object as the integration account — this machine is in the
domain and this account's rights are the question — and the container decides
what is wrong with it. `GET /connector/templates/{name}` returns the attributes as
stored; CEP would return the same ones, so the decision does not depend on the
transport.

| Code | Severity | Found when |
|---|---|---|
| `ca-unreachable` | Refusal | The connector did not answer. Reported alone, because a dozen unknowns under it would bury it |
| `ca-certificate-unavailable` | Unknown | The connector answered and the CA behind it would not hand over its own certificate — how a config string naming a CA that is not there looks |
| `agent-unusable` | Refusal | The enrolment agent is missing, expired, or not an enrolment agent |
| `agent-custody` | Warning | The agent's key is in a file, exportable, or its provider will not say |
| `revocation-unavailable` | Warning | Revocation is allowed and the account may not manage certificates |
| `no-template`, `template-unmapped` | Refusal | A profile has no template, so it cannot be issued |
| `template-not-published` | Refusal | The CA's own list does not include the template |
| `template-not-found` | Refusal | No template of that name in the forest — usually a display name |
| `template-supplies-subject` | Refusal | `msPKI-Certificate-Name-Flag` has 0x1: no SID extension, no logon since KB5014754 |
| `template-no-agent-signature` | Refusal | `msPKI-RA-Signature` is 0: the agent's signature proves nothing |
| `template-wrong-signature-policy` | Refusal | The required signature is not *Certificate Request Agent* |
| `account-cannot-enroll` | Refusal | The template's security descriptor does not grant Enroll to the account or any group in its token |
| `template-key-too-short` | Refusal, or Warning | `msPKI-Minimal-Key-Size` is longer than a key algorithm this deployment enrols with (`Blinky:Adcs:KeyAlgorithms`, all five when unset). The CA compares it with the key's length whatever the algorithm, so P-256 is 256 bits. A refusal when no configured algorithm gets through, a warning when some do |
| `template-key-algorithm` | Warning | A version 4 template names an algorithm in `msPKI-RA-Application-Policies` and the deployment also enrols with another. Not a refusal, because the CA does not enforce the algorithm: the lab CA issued an RSA 2048 key against a template naming `ECDH_P256` |
| `template-publication-unknown`, `template-unreadable`, `template-attribute-unknown` | Unknown | Something could not be read |

**Three outcomes, not a bool.** `Accepted` means nothing refused and nothing left
unestablished; `Unverified` means nothing refused and something could not be
checked; `Refused` is any refusal. The first version counted refusals only, and
its first run — a connector on a machine with no CA and no domain — reported the
registration **accepted**: the CA did not exist and the template could not be
read, and neither was a refusal. Unknown is its own severity now, and the same run
reports `UNVERIFIED` with `ca-certificate-unavailable` and `template-unreadable`.

**Enroll is evaluated the way templates are actually over-granted.** Full Control
and an extended-rights entry with no object type both grant it, and a check
looking only for the Enroll GUID would have refused templates the CA issues from.
A matching deny wins over any allow. Full Control is stored by the directory as
the mapped rights; the test for it was first written with SDDL `GA` — the generic
bit the directory never stores — and failed against correct code, so both forms
are accepted and both are tested.

**A service running as `LocalSystem` or `NetworkService` is judged as the
computer.** Those two reach the CA and the directory as `DOMAIN\MACHINE$`, so the
connector reads the computer object's `objectSid` and `tokenGroups` — which carry
*Domain Computers* — and adds *Everyone*, *Authenticated Users* and *This
Organization*, which a logon adds and the directory does not hold. The first run of
the check as the service evaluated the local `S-1-5-18` token instead and refused a
template the computer may enrol on; see *As the service* below.

**What it is not yet:** a registration. There is no flow that creates a CA
instance and refuses it — CA instances are not rows until 0022's open half — so the
check runs against the one CA the configuration names, when somebody asks. The
attribute names and the version 4 encoding of `msPKI-RA-Application-Policies` are
now confirmed on a real template; the policy is still matched by substring,
because that encoding packs several name–type–value triples into one string.

### 6. Deployment

- **`.env.example` and `docker-compose.yml`** — **done, and not run.**
  `CA_BACKEND`, the connector URL, its fingerprint, the client certificate and its
  password file, and the smart-card template, all defaulting to the built-in CA.
  **No enrolment agent key**: with the connector as the transport it lives on the
  Windows server, and a slot for one in the compose file would invite the
  arrangement this document moved away from. The compose file was edited on a
  machine without Docker and has not been parsed by `docker compose config`.
- **A client certificate for the API, and it is now the most sensitive file in
  the container.** It buys the enrolment agent's signature. Not an agent
  certificate: the agent CA issues workstation identities, and an agent that could
  impersonate the API to the connector would be able to enrol on anybody's
  behalf. A separate pair, its fingerprint in `AllowedClientThumbprints`, and
  eventually behind PKCS#11 for the same reason the master secrets are.
- **`installer/`** — holds `agent.wxs` and nothing else. The connector needs
  its own: service registration under a named account, the `%ProgramData%`
  directory, the firewall rule for `ListenUrl`, and the private-key grant that
  is otherwise the first thing to go wrong.
- **`docs/09-lab.md`** — a Windows AD + ADCS lab, an enrolment agent template
  and a copy of *Smartcard User*. The phase gate is the same enrolment against
  ADCS that already works against the built-in CA, and none of it can be
  checked without one.

### 7. The integration account — **still to do, and it has to be designed**

The connector issues and revokes certificates, so it needs a domain identity that
may do both, and that identity is the most powerful account this product asks a
customer to create. It is written down here so that it is designed rather than
created in a hurry on the day the lab is built.

What it has to hold:

- *Request Certificates* on the CA and *Enroll* on the smart-card template, for
  issuance.
- *Enroll* on the *Enrollment Agent* template and the agent certificate in its own
  store, generated there so the key was never exported.
- *Issue and Manage Certificates*, for revocation — and this is the grant to be
  careful with. As a CA role it covers every certificate the CA ever issued. ADCS
  can restrict a certificate manager to named users and groups, and a deployment
  should use that to confine this account to cardholders rather than hand it the
  whole CA.
- Ideally **Restricted Enrollment Agents** on the CA, limiting whom this agent may
  enrol for. Blinky recommends it in the registration check and does not require
  it.

Two arrangements hold up, and the lab started on the second:

- **A group managed service account**, with the agent certificate in its own store.
  Nobody holds its password, and nothing else on the server runs as it.
- **The computer itself.** A computer-bound agent certificate in `LocalMachine\My`,
  the service as `LocalSystem`, and Enroll granted to the computer account
  (`HZCS01$`). Also passwordless; the agent key is usable by anything running as
  SYSTEM on that server. This document first ruled it out, and was wrong to.

What it must not be: an administrator's own account, or a member of *Domain Admins*
"to get it working".

**What the lab ended up with is a third, hybrid arrangement**, and it is what issued
the first certificate. The service runs as a domain account, `AD\svc_blinky`. The
agent certificate is still the computer-bound one in `LocalMachine\My`, with its
private key readable by that account. Enroll on `BlinkySmartCardLogon` is granted
through a group, and the account holds the CA's certificate-management permission,
which the revocation probe confirmed. It works, and it has the costs of both
arrangements: the account has a password somebody set, and the key is still usable
by anything running as SYSTEM on the server. Whether the grant is *Issue and Manage
Certificates* alone or also *Manage CA* is not visible from the connector. The
first is all Blinky needs; the second lets the account reconfigure the CA, and an
account that also reaches the enrolment agent key should not have it. Neither Restricted
Enrollment Agents nor certificate manager restrictions are configured in the lab.

What it produces for Blinky to check, which is 0033: `describe` already reports
`AdminAvailable` and the agent. It does not yet report whether *Restricted
Enrollment Agents* or certificate manager restrictions are configured, and a
registration check that cannot see those cannot recommend them with any evidence.

Revocation through this account is 0034. `SupportsRevocation` follows
`AdminAvailable`, and the grant is the only thing standing between the connector
and every certificate the CA holds. Every revocation the connector performs is
logged with the serial, the reason and the calling client certificate.

### 8. `docs/STATUS.md`, `docs/status.json`, `docs/07-roadmap.md`

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

### The whole path, on a machine with no CA

Once `ConnectorAdcsTransport` existed, the same bench carried a request from the
container's side of the wire into `ICertRequest3::Submit`. The connector on
`127.0.0.1:18444`, a self-signed listener certificate pinned by fingerprint, a
client certificate in the connector's allowlist, and a self-signed enrolment agent
certificate carrying `1.3.6.1.4.1.311.20.2.1`:

```
dotnet run --project tools/AdcsProbe -- \
  --connector https://127.0.0.1:18444 \
  --client client.p12 --client-password ... \
  --fingerprint <sha256 of the listener certificate> \
  --ca-config 'CA01\Nonexistent Lab CA' \
  --submit BlinkySmartcardUser --agent agent.p12 --agent-password ... \
  --subject 'CN=jnowak'
```

| Asked | Answered |
|---|---|
| `describe` | The connector's version and schema, the CA config string, revocation unavailable, templates not established |
| `describe` with a fingerprint one digit out | Refused before any request, naming the pinning and the firewall rule as the two usual causes |
| `describe` with a client certificate not in the allowlist | 403, naming `Connector:AllowedClientThumbprints` on the CA server |
| `--submit` | `CCertRequest::Submit: RPC_S_SERVER_UNAVAILABLE (0x800706ba)` for a CA that does not exist |

That last row is the point. The enrolment agent's certificate was loaded, a CMC
was built and signed, it crossed the wire, and `ICertRequest3::Submit` was invoked
with those bytes. Everything between the container and the CA is proved; what is
unproved is the CA's opinion of the CMC.

It cost a third defect, of the same kind as the first two. `describe` failed
outright on this machine, which made a usable connector report as broken:
`ICertAdmin2` lives in `certadm.dll`, which arrives with the CA role or the
management tools, while `ICertRequest3` lives in `certcli.dll`, which is on every
Windows. The two can be present separately, and a machine with only the second can
enrol and not revoke. `AdminAvailable: false` is now the answer rather than an
exception.

One consequence of that, worth knowing before reading a `describe`: the wire
carries a bool, so `AdminAvailable: false` cannot distinguish a service account
without *Issue and Manage Certificates* from a machine with no `ICertAdmin2` at
all. Both mean revocation is unavailable. The connector's own log says which.

### The enrolment agent on the connector, on the same bench

After the key moved, the same run with the connector holding the agent certificate
and `tools/AdcsProbe --remote-agent`:

| Asked | Answered |
|---|---|
| `describe` | The agent's source, its provider — *Microsoft Software Key Storage Provider* — and `exportable: False`, reported as not production-ready because the source is a file |
| `--submit --remote-agent` | The container built the `PKIData`, the connector signed it, and a CMC of 1446 bytes reached `ICertRequest3::Submit`, answered `RPC_S_SERVER_UNAVAILABLE` |

And on the connector, the record this arrangement adds:

```
Signed as enrolment agent for CN=jnowak, key 29CB236D…CCF18F2, asked by DA85B5AF…BC81495
Submitting a Cmc request of 1446 bytes to CA01\Nonexistent Lab CA
```

Two things this run did **not** exercise, because doing so would have meant
importing an enrolment agent certificate into the store of the person running
it: loading the agent from `CurrentUser\My` by fingerprint, and a key that is
genuinely non-exportable in a store. Both were run from a file. The store path is
the first thing to try on the lab server.

It also found a defect in how this was being checked rather than in the code. A
build of the probe failed and the command carried on, because it was chained with
`&&` after `grep | head`, whose exit status is not the build's. The probe that ran
was the previous one. Nothing was concluded from that run.

### On HZCS01, a real domain member, with a real enrolment agent

Windows Server 2022 Datacenter, joined to `ad.digitalworkspace.pl`, reached over
OpenSSH with a key as its local administrator. No Certificate Authority role, no
.NET runtime. The connector went there as a self-contained build in
`C:\Blinky\AdcsConnector`, listened on `127.0.0.1:8444` only, and was reached
through `ssh -L`, so no firewall rule was needed. The enrolment agent certificate
was enrolled onto the computer by the lab's owner from a template called
`BlinkyEnrollmentAgent(Computer)`, issued by *DigitalWorkspace Issuing CA -
homelab*.

| Asked | Answered |
|---|---|
| Start, listener from a PKCS#12 | **Died**: `Access denied` importing the key. Fixed, see below |
| `describe`, no CA named | 502: no certification authority active on this machine |
| `describe`, a CA named that does not exist | Revocation reported **available**. Wrong, fixed, see below |
| `--check`, same | `UNVERIFIED`: the CA did not hand over its certificate; the template could not be read — *the specified domain either does not exist*, because a local account on a domain member cannot read the directory |
| `describe` with the real agent by SHA-1 fingerprint in `LocalMachine\My` | `store: LocalMachine\My`, *Microsoft Enhanced Cryptographic Provider v1.0*, `exportable: False`, production-ready — matching `certutil`'s *Private key is NOT exportable* |
| `--submit --remote-agent` | **Signed** by the real, non-exportable agent key; a CMC of 2718 bytes reached `ICertRequest3::Submit` and got `RPC_S_SERVER_UNAVAILABLE` for a CA host that was a placeholder |

Four things were learned there that could not have been learned on the bench:

1. **A key-authenticated session cannot import a key for its own user.** DPAPI
   protects a user-key-set import with the user's master key, and a logon without
   the password has none. Measured in that session, loading the same file:

   | Key set | Result |
   |---|---|
   | default, user | `Access denied` |
   | machine | loaded |
   | ephemeral | loaded |

   A service started by the service control manager has the credential, and so
   does an interactive logon; a scheduled task set to run without storing a
   password does not. `Pkcs12File` now tries the user key set and falls back to
   the machine key set, and the log says which it used. Not the ephemeral set:
   Schannel will not serve TLS from a key that was never persisted.
2. **`certadm.dll` ships with Windows Server.** So `ICertAdmin2` was there, the
   revocation-permission probe really ran, and an RPC failure against a CA that did
   not exist was read as "got as far as the database". The probe now runs only when
   the CA handed over its certificate, treats the RPC facility and a CA-not-found as
   "unavailable", and logs the code it saw. What a *real* CA answers for an
   unknown serial is still unobserved.
3. **The connector need not be on the CA.** `ICertRequest3` and `ICertAdmin2` both
   take a remote config string, and a member server was enough. The one thing lost
   is the template list, which is read from the CA's own registry and is then
   unknown rather than empty.
4. **The legacy CSP signs SHA-256 here.** The agent key is in the *Enhanced
   Cryptographic Provider*, which under CryptoAPI cannot do SHA-256; .NET reached it
   in a way that could, and the CMS signature was produced. Worth knowing before
   anybody "fixes" the template's provider.

**And one assumption in this document turned out to be wrong.** It said a
connector running as `LocalSystem` enrols as the machine account, "which is not an
identity anybody can grant Enroll to in a way that means what they intended". The
lab's owner chose exactly that: a computer-bound enrolment agent. It is a coherent
arrangement — the requester is `HZCS01$`, Enroll on the smart-card template is
granted to that computer, the service runs as `LocalSystem`, and there is no
password anywhere. Its cost is that the agent key is usable by anything running as
SYSTEM on that server, which is the same population that already administers it.
Section 7 now lists both.

### First contact with the CA and the forest

Later the same evening the lab's owner started the connector on HZCS01 in their
own session, as `AD\Administrator`, and it was reached through the same tunnel. The
CA is *DigitalWorkspace Issuing CA - homelab* on `SUBCA` (`172.16.2.16`).

| Asked | Answered |
|---|---|
| `describe`, `SUBCA\DigitalWorkspace Issuing CA - homelab` | The CA handed over its chain, 3532 bytes. Revocation reported available. Template list unknown, because it lives in the CA's registry and the connector is not on the CA |
| `--check BlinkyEnrollmentAgent(Computer)` | The template was **found and read out of the forest** — a name with parentheses in it, through the escaped filter — every attribute readable, Enroll evaluated for the account. Refused for requiring no authorised signature, which is right for an agent template and was the point of reading one: the smart-card template's name is not known here yet |

What that settles, and what it does not:

- **The config string is the host and the CA's common name.** `SUBCA`, not the
  computer account `SUBCA$`, and the name as the issuer field spells it, including
  `- homelab`.
- **Every config string failed identically from a key-authenticated SSH session**,
  including a host that does not exist: `RPC_S_SERVER_UNAVAILABLE` in under 32
  milliseconds, with port 135 open. A local account cannot authenticate DCOM to a
  domain CA, and the error it gets says nothing about why. Reaching the CA needs a
  domain identity — the service as the computer, or a person's session.
- **The directory read works on a real forest.** The attribute names from MS-CRTD
  are the right ones and are readable by an ordinary domain account; the version 4
  encoding of the signature policy is still unseen, because the template read
  requires no signature at all.
- **The revocation probe is still not proven.** The real CA answered the probe with
  `0x80070057`, *the parameter is incorrect*, which the probe reads as "got past
  the permission check". The account was a domain administrator, so "available" is
  very likely true here — but an invalid-parameter answer may well come before the
  permission check, in which case an account without *Issue and Manage
  Certificates* gets the same answer. The run that decides it is the same probe as
  an account without that right, and until then `AdminAvailable` is a guess with a
  logged code behind it.
- **The Enroll answer was for the administrator**, not for the identity the
  service will run as. With a computer-bound agent that identity is `HZCS01$`.

### As the service, as the computer

The lab's owner installed the connector as the service `BlinkyAdcsConnector`
running as `LocalSystem` and created the smart-card template
`BlinkySmartCardLogon`. It was reached through the same tunnel.

| Asked | Answered |
|---|---|
| `describe` | **The CA in `Connector:CaConfig` was not the one asked.** The setting was documented, in the lab's configuration, and never read: the connector took the CA from the request or the local `ICertConfig`, and on a machine with no CA said so while naming the setting it had ignored. Fixed; the order is the request, then the setting, then the local machine |
| `describe`, fixed | Chain 3532 bytes. Agent from `LocalMachine\My`, not exportable. Revocation **not available**: the probe answered `0x80070005`, access denied |
| `--check BlinkySmartCardLogon` | **Refused, `account-cannot-enroll` for `NT AUTHORITY\SYSTEM`** — the check's error, not the template's. Fixed as described in section 5 |
| `--check BlinkySmartCardLogon`, fixed | `UNVERIFIED`: Enroll found for `AD\HZCS01$`, nothing refused; revocation unavailable (warning) and template publication unknown, because the CA's list is in its registry on `SUBCA` |

What that settles:

- **The revocation probe discriminates.** The same probe against the same CA
  answered `0x80070057` as `AD\Administrator` and `0x80070005` as `HZCS01$`,
  which holds no *Issue and Manage Certificates*. So the invalid-parameter answer
  comes after the permission check, and "available" and "unavailable" were both
  read correctly. One CA and two identities, not a proof for every CA version.
- **The version 4 signature policy looks the way MS-CRTD says.**
  `BlinkySmartCardLogon` is schema 4 and stores the policy as
  `` msPKI-RA-Application-Policies`PZPWSTR`1.3.6.1.4.1.311.20.2.1` ``. One
  authorised signature, name flags `0x82000000` — subject from the directory, UPN
  required, nothing supplied by the request — and the EKUs *Smart Card Logon* and
  *Client Authentication*. Every attribute check passed.
- **A computer-bound arrangement holds together short of a submission.** The
  service reaches the CA and the forest as the computer, which a key-authenticated
  SSH session never could.

The lab is deliberately generous: its owner runs it as a domain administrator.
Nothing measured here says what a least-privileged integration account needs,
which is still section 7's question.

### The first certificate

With the service running as `AD\svc_blinky` (section 7), `AdcsProbe --submit
BlinkySmartCardLogon --remote-agent --requester AD\BlinkyUser` sent the CMC built by
`CmcRequest`, signed by the connector, to the CA. Done with the lab owner's consent,
for a test account, with a key the probe generated and discarded.

| Attempt | Answer |
|---|---|
| ECC P-256 key, as a card would have | **Denied by Policy Module, `0x80094811` `CERTSRV_E_KEY_LENGTH`**: the key is shorter than the template's minimum. The request is in the CA's failed requests with that message |
| RSA 2048 key, `--key RSA2048` | **Issued.** Serial `47000000097012D4FEBA5C0A0E000000000009`, chain of three |

What the issued certificate says, and why each part matters:

- **Subject `CN=BlinkyUser, OU=Users, OU=DIGITALWORKSPACE, DC=ad,
  DC=digitalworkspace, DC=pl`.** The request asked for `CN=BlinkyUser`. The CA
  ignored it and built the subject from the directory object that `requestername`
  named, so the `RegInfo` control was read and used.
- **UPN `BlinkyUser@ad.digitalworkspace.pl`** in the subject alternative name, from
  the same object.
- **The SID extension `1.3.6.1.4.1.311.25.2`** carries
  `S-1-5-21-3474637876-781497690-2719985338-1132`: the strong mapping KB5014754
  requires. It is there because the template takes the subject from the directory.
- **Not issued for the requester.** Neither `svc_blinky` nor `HZCS01$` appears.

So the EOBO shape is what a Microsoft CA accepts. That includes the order of the
two SignerInfos as DER encodes the `SET OF`, which was the last unchecked point.

**What the key-length denial means for the product.** The profiles name `ECCP256`,
and the agent generates RSA 2048 unless an enrolment asks for another algorithm,
because Windows does not offer an ECC smart-card certificate at logon without
`EnumerateECCCerts`. So which key reaches the CA is chosen per enrolment. A
template left on the default cryptography settings (legacy CSP, RSA, minimum 2048)
denies every ECC key, and the CA only says so at submission. It is a template
setting: a minimum of 256 lets both lengths through, and a version 4 template on a
*Key Storage Provider* also names one algorithm.

**Now checked before a card is involved.** The connector reads
`msPKI-Minimal-Key-Size`, and the registration check sets it against the key
algorithms the deployment enrols with (`template-key-too-short`, section 5). Against
`BlinkySmartCardLogon` it answers with a warning that ECCP256 and ECCP384 will be
denied with `CERTSRV_E_KEY_LENGTH`, which is what the CA did. A denial with that
code now also says, in Blinky's own words, that an ECC key is measured in its own
bits.

**One template takes both.** The lab's owner set `BlinkySmartCardLogon` to a
*Key Storage Provider* with an ECC algorithm; the directory then held
`msPKI-Asymmetric-Algorithm` `ECDH_P256`, not the ECDSA the owner chose, and a
256-bit minimum. With the same test account, a P-256 key issued
(`470000000A1FCD49636F1BFBDA00000000000A`) and an RSA 2048 key issued
(`470000000BE836A32CA027F38100000000000B`), a second apart. So the CA enforces the
minimum key size and not the algorithm the template names, and a minimum of 256 lets
a card be issued with either. Both certificates were revoked through the connector
straight afterwards.

Two things that run did not show. The first is the key usage of the ECC
certificate, which matters for logon, because a certificate that allows only key
agreement cannot sign a PKINIT request. The probe did not print it then and does now,
and the revoked certificate can still be opened in the CA console. The second is an
earlier reading of this document: after the template was first moved to a *Key
Storage Provider* with RSA, the directory held `msPKI-Asymmetric-Algorithm` `RSA`
explicitly. Before that move there was no such value at all, because a legacy
provider names none, not because RSA as a default goes unwritten.

**The test certificate was revoked** through the connector the next day with
`AdcsProbe --revoke`, which goes through `AdcsCertificateAuthority.RevokeAsync` - the
API's path - reason *cessation of operation*. The CA accepted it, and the connector
logged the serial, the reason and the fingerprint of the client certificate that
asked, as it now does for every revocation. That the CA lists it as revoked has not
been read back here; the CA console or the next CRL shows it.

### What a Microsoft CA requires of a CMC on somebody's behalf

**This was the blocker for 0030's definition of done, found by reading, not by a
CA. The shape is written, and the lab CA has issued from it** — see *The first
certificate* above. [MS-WCCE, *Enroll on Behalf of Certificate Request Using CMS and CMC
Request Formats*](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/2d1cf183-2507-4026-bc05-7b6b65dfced9)
and Microsoft's own [annotated CMC EOBO request](https://learn.microsoft.com/en-us/windows/win32/seccertenroll/cmc-eobo-request)
agree on two things `CmcRequest` does not produce:

- **Who the certificate is for travels in the CMC**, as a `RegInfo` control
  (`1.3.6.1.5.5.7.7.18`) whose value MUST include `requestername`. The value is
  UTF-8, `Name=Value` pairs joined by `&`, and the requester name is
  `DOMAIN\user` — [MS-WCCE 2.2.2.6.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/40e555ec-a9e2-4f2c-84ff-7aef6f1e0b0a).
  Without it the CA has nobody to build the subject for except the requester,
  which with this lab's agent is the computer.
- **At least two SignerInfos.** The first is either signed by the enrollee's own
  key and identified by subject key identifier, or uses the no-signature
  mechanism; the second is the enrolment agent. `CmcRequest` produces one.

What it took:

- **The cardholder's `DOMAIN\sAMAccountName`.** `CardholderIdentity` has an
  optional `LogonName`, and `AdcsCertificateAuthority` refuses to issue without it
  before the agent is even opened. The API fills it at issuance when the backend is
  ADCS (`LogonNames`): the directory is asked for the enrolment's UPN, the account
  it returns has to carry the SID the enrolment was created for, and the NetBIOS
  name comes from the domain's `crossRef` in the Configuration partition, or from
  `Blinky:Directory:NetBiosDomain`. A UPN that has moved to another account is
  refused rather than issued for, because the CA builds the certificate for
  whoever the name points at. **Written and unit-tested; the `crossRef` read has not
  run against a directory**, and no enrolment has gone from the console to ADCS.
  `AdcsProbe --requester DOMAIN\user` still supplies the name by hand.
- **`CmcRequest` writes the `RegInfo` control**, body part 2, before the request's
  body part 1, with `requestername=DOMAIN\user` and nothing else. A name with a
  second backslash, `&`, `=` or a control character is refused rather than
  escaped. The template stays in the attribute string.
- **`PkiDataInspection` allows exactly one `RegInfo` and nothing else**, and
  refuses one without `requestername`, one that shares a body part ID with the
  request, and a name that is not `DOMAIN\user`. The connector logs the requester
  name for every signature — the subject a card writes into its PKCS#10 is not what
  ADCS issues, and the requester name is.
- **The connector adds a no-signature SignerInfo beside the agent's**, using
  `SubjectIdentifierType.NoSignature`. The file-based store does the same, and a
  test holds the two shapes equal. A no-signature signer is verified by its hash:
  `SignedCms.CheckSignature` looks for its certificate and fails, which is true and
  beside the point, and cost a round of red tests to learn. The alternative, a
  SignerInfo from the card's key, would cost a second card operation and a second
  PIN, and is only worth it if the CA refuses this one.
- **An order to check on a CA.** `SignerInfos` is a DER `SET OF`, so "first" and
  "second" are an encoding order, not an insertion order. The CA accepted the
  encoding order.

## Unverified, and named as such

A Microsoft CA has answered describe and the revocation probe, the forest has
answered the template checks, and the CA has issued a certificate from a CMC in the
shape above, for the user it named. No card key has been issued, and nothing has
been revoked at the CA. It
builds, it starts, it refuses what it should refuse, its access control and parsing
are under test, and a signed CMC has reached `ICertRequest3::Submit` on a machine
with no CA behind it. That is all that is claimed. What a real ADCS thinks of the CMC is the open question, and it
is the whole of 0030's definition of done.

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
