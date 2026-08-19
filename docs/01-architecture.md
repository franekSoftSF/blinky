# 01 — Architecture

## The shape of the system

Blinky is four processes and one database. Three of them run in Docker; the
fourth runs on the workstation, because that is where the reader is.

```
Docker                                    Workstation (Windows / Linux)
┌────────────────────────────┐            ┌──────────────────────────────┐
│ frontend  Angular + nginx  │            │ Agent.Service  (LocalSystem) │
│     │ /api → api:8080      │            │   ├─ PC/SC session           │
│     ▼                      │  HTTPS     │   ├─ job executor            │
│ api       REST + SignalR   │◄──────────►│   └─ named-pipe server       │
│     │         ▲            │  WSS       │            ▲                 │
│     ▼         │            │            │            │ pipe            │
│ postgres      │            │            │ Agent.Ui   (user session)    │
│     ▲         │            │            │   PIN · touch · Kerberos     │
│     │         │            │            └──────────────────────────────┘
│ worker  jobs, CRL, expiry  │                          │
└────────────────────────────┘                          ▼
             │                                    YubiKey 5 (CCID)
             ▼
      ICertificateAuthority
       ├─ BuiltInCa   → SoftHSM2 / PKCS#11 / file
       └─ AdcsCa      → CES/CEP over HTTPS, or AdcsConnector over DCOM
```

## Why the agent is not in Docker

The agent needs a PC/SC session against a USB CCID device attached to the
user's machine, and it needs to run at the moment that user is sitting in front
of it. Neither survives containerisation, and USB passthrough into a container
on an end-user desktop is not a deployment story anybody wants to support.

Same reasoning as the FAG agent needing local NTFS: the container boundary ends
where the hardware begins.

## Two processes on the workstation, not one

`Agent.Service` runs as LocalSystem in session 0. It owns the card, holds the
PC/SC context, and executes jobs. It cannot draw a window a user will see.

`Agent.Ui` runs in the interactive session, per user. It draws the PIN prompt,
the "touch your key now" prompt, and — critically — it is the only component
that can obtain a **Kerberos ticket for the person actually logged in**.

The split exists for two independent reasons, and either one alone would force
it:

1. **Session 0 isolation.** A service cannot show UI. PIN entry and touch
   prompts are UI.
2. **Identity.** LocalSystem's identity is the *machine*. Issuing a credential
   to a cardholder requires proof of *who is at the keyboard*, and the only
   cheap, strong proof available is the user's own Kerberos ticket, obtained in
   their own session.

They talk over a named pipe with a fixed ACL: the service accepts connections
only from the interactive session's user, and never persists a PIN —
`Agent.Ui` collects it, the service uses it for one command and zeroes it.

## Transport: HTTPS + SignalR, not a broker

CredLoop uses MQTT because there is already an on-premises server hosting the
broker and the fleet is push-heavy. Blinky does not, and adding Mosquitto
would mean a second listener, a second credential store, and a second ACL model
to get wrong.

Instead:

- **REST over HTTPS** for everything the agent initiates (register, heartbeat,
  claim job, submit CSR, report result). That is the majority of the traffic.
- **SignalR over WSS on the same port** for the one thing the server initiates:
  "you have work". The message carries no payload — it is a doorbell. The agent
  then claims the job over REST.

Consequences worth stating plainly:

- One port, one certificate, one auth model. Goes through corporate proxies
  because it is HTTPS.
- If the socket is down the system still works, just later: the agent polls on
  a slow interval as a floor. The doorbell is an optimisation, never a
  correctness requirement.
- Scaling `api` past one replica needs a SignalR backplane (Redis). Documented,
  not built, until there is a reason.

Because the doorbell carries no state, swapping SignalR for MQTT or SSE later
touches one class on each side.

## The job engine is in the worker, not the API

The API scales horizontally. The lifecycle scanner — "which credentials expire
in 30 days, which cards have not checked in, which CRLs are stale" — does not.
Two API replicas both running the expiry scan means two renewal jobs for the
same credential and a user asked to touch their key twice.

So the `worker` container is a single replica by design and owns:

- expiry and renewal scanning,
- job timeout watchdog,
- CRL regeneration and publication,
- OCSP responder feed,
- retention and audit compaction.

The API creates jobs on user request and hands out work. It never decides on
its own that work exists. Exactly the Orchestrator/API split from FAG, for the
exact same reason.

## PKI behind one interface

```csharp
public interface ICertificateAuthority
{
    string Backend { get; }                       // "builtin" | "adcs"
    Task<CaCapabilities> DescribeAsync(CancellationToken ct);
    Task<IssuedCertificate> IssueAsync(CertificateRequestContext ctx, CancellationToken ct);
    Task RevokeAsync(RevocationRequest req, CancellationToken ct);
    Task<CrlDocument> GetCrlAsync(string caId, CancellationToken ct);
}
```

`CertificateRequestContext` carries the PKCS#10 produced by the card, the
verified attestation chain, the resolved cardholder identity (UPN, SID, DN) and
the profile name. What each backend does with it differs completely; what the
job engine sees does not.

`CaCapabilities` is how the difference leaks in a controlled way: whether the
backend accepts a caller-supplied subject, which algorithms it takes, whether
it can revoke, and whether it publishes a CRL. The UI greys out what the
selected backend cannot do rather than failing at issuance time.

Both implementations are built from the start. The built-in CA is the one that
gives an end-to-end `docker compose up` demo with no directory at all; ADCS is
the one that matters in a Windows shop. Neither is a stub.

See [04 — PKI backends](04-pki-backends.md).

## Directory integration is a separate axis from PKI

Do not conflate "where do certificates come from" with "where do identities
come from". Blinky treats them as two independent choices:

| Directory | Identity source | Realistic CA choice |
|---|---|---|
| Windows AD | LDAP + Kerberos | ADCS, or built-in CA published into AD |
| Samba4 AD DC | LDAP + Kerberos (same protocols) | Built-in CA — Samba4 has no ADCS |
| None (lab, SMB) | Local users in Blinky | Built-in CA |

The Samba4 case is not a second product. It is the built-in CA plus publication
of the CA certificate into the directory so that smart-card logon and PKINIT
work. That publication step is the only Samba-specific code, and it is small.

## Deployment topology

```
docker compose up -d
  frontend   nginx :80   → Angular bundle, proxies /api to api:8080
  api        :8080       → REST + /hubs/agents
  worker                 → no listener
  postgres   :5432
  softhsm    (volume)    → built-in CA key material, dev profile
```

`frontend` proxying `/api` means the browser sees one origin: no CORS, and the
same built bundle runs in dev, test and production. Straight port of the FAG
decision.

The agent ships as an MSI (WiX) with the backend URL and enrolment token as
properties, written into the service's environment key in the registry so .NET
configuration picks them up natively — again the FAG pattern, because it works
and needs no custom actions.

## Out of scope for v1

Stated here so it does not have to be argued later:

- **Non-YubiKey tokens.** The PIV layer is written against the standard, but
  attestation, management-key policy and metadata are Yubico-specific. Other
  vendors are a later interface, not a v1 `if`.
- **Virtual smart cards / TPM.** A different key attestation story entirely.
- **A Windows credential provider.** Logon-screen PIN reset is a Phase 5+ item,
  C++/COM, and it can be lifted from CredLoop when it exists there.
- **Key escrow for encryption certificates.** The `9D` key management slot
  invites it; doing it properly means a key recovery agent workflow and a
  second custody model. Deferred, but the data model reserves room.
