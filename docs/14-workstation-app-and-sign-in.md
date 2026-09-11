# 14 — The workstation app, and signing in

Written before it is built, which is the point. Nothing in this document is
implemented; what is here is the direction and the three places where it
collides with something already decided.

## What changed

Two complaints, and the second one is the load-bearing half.

**A window nobody asked for is a window nobody understands.** Today a prompt
appears because a job reached the service: the person at the keyboard did not
start anything, is not expecting anything, and is being asked for a PIN by a
dialog that arrived on its own. That is a bad shape for a credential ceremony
and a worse one for training people — the correct response to an unexpected
password prompt is suspicion, and we are teaching the opposite.

**So the person starts it.** Enrolment happens *after* somebody opens an
application and signs into it. The app can still be brought to the front when
there is work waiting, but it is an application the user already knows, already
signed into, and can take their time inside. A key ceremony is not an
interruption to be dismissed; it needs the minute it needs.

## The shape

Angular in a **Tauri v2** shell, following
`WSOAuditTool` — Angular 22, WebView2, bundled as MSI and NSIS. The reasons
that hold there hold here: no second runtime to deploy on the workstation for
the UI, a small installer, and native HTTP outside the browser's origin rules.

It also means **one UI technology for the whole product**. The console is
Angular. A tray written in WPF and a console written in Angular are two
languages, two toolkits, two sets of components and two people who can change
them.

### The workstation app looks like the console, because it is the console

Not a second design. The same components, the same look, the same behaviour for
the same things — a token row, a slot, a job that is waiting for somebody. An
operator who has used one has used the other.

That has a structural consequence worth taking early. `frontend/` is a
single-project Angular workspace today: one application, at the root, called
`frontend`. Sharing anything means splitting it into a library and two
applications — the console, the workstation app, and the components both use —
and doing that after both exist means moving every file twice.

Both are Angular 22 already, which is also what `WSOAuditTool` runs, so nothing
has to be reconciled to make this possible. It only has to be done before the
second application starts rather than after.

The shared half is components and presentation. The unshared half is how each
reaches its data: the console calls `/api` on the server, the workstation app
calls the agent on the loopback, and neither should learn the other's client.

## The seam: a local API, chosen over the pipe

The service grows **a small HTTPS API on the loopback interface**, with its own
local certificate, and the app talks to that. The app does not talk to the
Blinky backend at all: it asks the agent, and the agent — which already holds
the machine's mTLS identity and already knows how to reach the server — carries
the request. One channel out of the workstation, owned by the component that
was always going to own it.

**Keeping the named pipe was possible and was rejected.** The usual argument
for the socket — that WebView2 cannot open a pipe — does not actually hold:
every call has to go through a Tauri command into Rust anyway, for reasons in
the next section, and Rust opens a named pipe as easily as a socket. The pipe
would have kept an ACL the operating system enforces, and cost nothing to keep.

It was rejected for shape rather than for capability: the whole product already
speaks HTTP and JSON, a loopback API is the same client code as everything else
the app does, and it leaves room for something other than this one application
to talk to the agent later. That is a reasonable trade and it is a trade —
what it costs is below, in full, because the cost is paid in security rather
than in effort.

Two things survive from [10 — The agent UI](10-agent-ui.md) and must:

- **The app never touches the card.** Every APDU stays in
  `Blinky.Agent.Service`, which owns the reader. The app renders and asks; it
  holds no PC/SC handle, no PIN beyond the moment it sends one, and no card
  state of its own.
- **The service stays, and stays LocalSystem.** It renews its own certificate
  from the machine store, polls for work, and runs an inventory sweep on a
  machine where nobody is logged in. An application that exists only while
  somebody is signed in cannot do any of that.

### What the pipe was doing that a socket does not

This is the part that cannot be waved through. Doc 10 is explicit that the
pipe's ACL stopped being about answering a prompt and became **the thing
standing between being logged in at this machine and acting on the token in
it**. That ACL was `INTERACTIVE` and `LocalSystem` and nothing else, and the
operating system enforced it.

**A listener on `127.0.0.1` has no ACL.** It is reachable by every process of
every user on the machine — a second signed-in session, a low-integrity
sandbox, anything. Moving the seam to a socket deletes the guarantee unless it
is rebuilt on purpose. Four things rebuild it, and all four are required rather
than alternatives:

- **The caller's identity, checked per connection.** Windows will name the
  process at the other end of a loopback connection — `GetExtendedTcpTable`
  gives the owning PID, and from it the session and the user's SID. The service
  accepts only a process running as the **interactive user of the console
  session**, which is what `INTERACTIVE` meant. A request from another user's
  session is refused, not served.
- **A per-user secret, and a port nobody can squat.** The service binds an
  ephemeral port and writes the port and a fresh token into a file under that
  user's own profile, readable by that user and `SYSTEM` and nobody else. A
  fixed port is a port another process can take first, and an unauthenticated
  local port is a port anything can call.
- **`Origin` refused outright.** A browser can reach `127.0.0.1`. Any page the
  user visits can issue requests at this API, and DNS rebinding turns a
  same-origin check written casually into no check at all. The API serves only
  requests carrying **no** `Origin` — which a native client sends and a browser
  cannot suppress — and never emits a CORS header. This is the failure mode
  that has produced a long line of local-agent advisories; it is not
  hypothetical and it is cheap to close.
- **The certificate is pinned, never trusted.** Generated at install, held by
  the service, and **pinned in the app** — not added to any Windows trust
  store. A machine-wide root installed so that one local app can talk to one
  local service is a machine-wide root, and it is exactly the thing this
  product exists to argue against.

The last one decides something about the app's internals: **the Angular code
must not call the API with `fetch`.** A request from the WebView is judged by
the browser engine, which would need the certificate in a trust store to accept
it. The calls go through a Tauri command into Rust, and Rust does the TLS with
the pin — which is the same reason `WSOAuditTool` puts its HTTP in the native
layer.

So: the service gains a loopback listener, `Blinky.Agent.Ui` and the pipe are
replaced together, and the pipe's ACL is re-created in four pieces that a code
review can check one at a time.

## What it costs, stated rather than skipped

`Blinky.Agent.Ui` is **finished**. Patches 0046, 0047, 0048 and 0048a are done
and proved on hardware: the certificate list beside what the backend holds, PIN
set and change with the policy enforced in the service, unblock online and
unblock over a telephone, in Polish and English, light and dark. Two of its
defects were found only by running it.

None of that is wasted knowledge and all of it is wasted code. The new app
re-implements every one of those screens. That is the price of the change and
it should be paid deliberately, not discovered in the third week.

**It retires at parity, not before.** WPF is the reason for the change — a
toolkit nobody else in this product uses, and one the console cannot share a
line with — but a half-finished replacement that ships beside it means two
clients on one local API and two places to fix the same defect. So
`Blinky.Agent.Ui` stays installed and unchanged until the new app does
everything 0046 through 0048a do, and is removed in one commit when it does.

What survives untouched: the service's card work, the PIN policy enforced
inside it, the offline unblock derivation, and every test around them. What
does **not** survive is the named pipe and its ACL — see the seam above, which
is where most of the risk in this phase lives.

## Signing in, on the workstation

Two methods, chosen by deployment rather than by the user.

**Kerberos.** Already the design — [05 § Two identities](05-agent-protocol.md)
has the user's identity arriving as a SPNEGO ticket from the interactive
session, because `Agent.Service` runs as LocalSystem and can only ever prove
the machine. The app fetches the ticket and hands it over for a single request.
Nothing about that changes; it moves from a WPF process to a Tauri one.

**A password.** The new part, and the one that needs care. It exists for the
machine that is not in a domain — a contractor's laptop, a kiosk, a lab box —
where there is no ticket to fetch and no directory to ask.

Three rules that come with it:

- The password is verified **at the backend**, never on the workstation. The
  agent must not become a thing that can be made to say yes.
- Stored as a modern password hash with a per-user salt, and nowhere else.
  This is not the PIN rule bending: a PIN is never stored *in any form* because
  it authenticates a person to a card that has its own retry counter. A
  password authenticates a person to this server, and a server that cannot
  check a password cannot have password sign-in.
- **Rate-limited and lockable, per account.** A card gives you three tries. An
  HTTP endpoint gives you as many as you like unless somebody says otherwise.

## Signing in, to the admin panel

**This is a reversal, and it is recorded as one.** Patch 0053a says:

> A system for managing smart cards whose operators sign in with smart cards is
> the only honest arrangement.

The new direction is a bootstrap **superadmin account** with a password and
**TOTP** as a second factor, with FIDO2 later.

The reversal is defensible, and the reason is one 0053d already half-states:
**you cannot require a smart card to sign into the system that issues smart
cards, before it has issued any.** There has to be a way in that does not
depend on the product working. 0053d called that a break-glass; this makes it
the front door and the certificate the upgrade.

What the honest version of that looks like:

- One superadmin, created at deployment, **password plus TOTP from the first
  sign-in** — not a password today and a second factor when somebody gets
  round to it.
- The certificate path from 0053a is **not cancelled**. It becomes what an
  operator moves to once operators have cards, and the thing an administrator
  can require per role.
- FIDO2 as a second factor arrives with Phase 7's CTAP2 work rather than
  beside it. Registering a passkey for an operator of this console is the same
  ceremony as registering one for a directory user, run against ourselves.
- TOTP needs recovery codes, shown once, or the first lost phone is a
  break-glass event.

## Why the console's sign-in comes first

Of everything in this document, this is the part that is not an improvement but
a repair.

The console has no accounts. One `X-Blinky-Operator` token stands for every
operator: the audit trail cannot name who revoked a credential or disclosed a
PUK, nothing expires, nothing can be withdrawn from one person without
withdrawing it from everybody, and a shared secret ends up in shell history and
in a chat window because that is what shared secrets do. A system whose purpose
is proving who holds which credential cannot currently say who is operating it.

0053 has said so since it was written. What changes now is that there is a way
to fix it that does not wait for every operator to have a card: 0086 and 0087
here, with 0053b, 0053c and 0053e from Phase 5. Those five are one piece of
work — an account, a second factor, a session that can be ended, a role that
limits what the account may do, and a named credential for the scripts so the
shared token can be deleted rather than merely deprecated.

0053a, the certificate, is the upgrade after that and is not in the way of it.

## Enrol on behalf of

Patch **0023a** is already in the roadmap and already marked *essential*: an
operator asking for a certificate in somebody else's name is the normal case,
and today the only thing between that request and a certificate asserting a
stranger's identity is a shared token in a header.

The new direction wants it exercised, and through **the same ceremony** — the
operator drives it from the console, the card is at the cardholder's
workstation, the app there runs the ceremony, and the agent never becomes the
requester.

One consequence worth flagging now. 0023a says the evidence should be an
**enrolment agent's signature** from a certificate that says it may do this
(`1.3.6.1.4.1.311.20.2.1`), and that naming *which operator* asked waits for
operators to have certificates. If operators sign in with a password and a TOTP
code instead, that dependency breaks: the enrolment agent certificate would
belong to the **service**, and which human asked would be an authenticated
audit record rather than a cryptographic fact. That is weaker, it is probably
acceptable, and it is exactly the kind of thing that must be decided on purpose
rather than discovered in an audit.

## Every new model gets full CRUD

Adopted, with one exception that has to be part of the rule rather than an
afterthought.

**The rule.** A new entity arrives with list, read, create, update and delete,
and the admin panel can manage it. A model that exists in the database and
nowhere in the UI becomes a thing only the person who added it can change.

**The exception: a record of something that happened is not editable.** Audit
events, jobs, credentials and PUK disclosures are history. A credential is not
deleted when a card is lost — it is revoked, and the row outlives the card,
which is the whole point of [02](02-data-model.md)'s state machines. An audit
trail that supports `DELETE` is not an audit trail.

So the rule reads: **full CRUD for anything that describes configuration or
people; create-and-transition for anything that records an event.** The second
list is short and known — `AuditEvent`, `Job`, `Credential`, and the disclosure
rows — and everything not on it gets the full five.

## Settled, and what is left open

**Settled on 11 September 2026.** The seam is a loopback HTTPS API and not the
named pipe, for the reason above and with the four checks above as its price.
The workstation app is Angular in a Tauri v2 shell. `Blinky.Agent.Ui` is
replaced rather than kept, and retires at parity in one commit. The workstation
app and the console share one component library, split out of `frontend/`
before the second application is written.

**Still open, and a decision rather than research:**

| Question | Why it cannot be settled here |
|---|---|
| Does operator authentication by certificate stay the target, with password and TOTP as the way in — or does it become optional? | It decides whether 0023a's enrolment-agent signature names a person or a service, which is the difference between cryptographic evidence and an audit line. The suggestion on the table: superadmin is password and TOTP forever, because it is the way back in when nothing else works; operator moves to a certificate once operators have cards |
