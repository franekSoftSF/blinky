# 10 — The agent UI

What the person at the keyboard can see and do, and where the boundary sits
between asking and being allowed.

Patch 0018 built one window: the service needed a PIN, drew a prompt in the
user's session, and got an answer. This document covers what comes after that —
a tray-resident UI that lists certificates, renews them, and changes, sets or
unblocks a PIN.

## The change nobody should skim past

0018's pipe runs in one direction of *intent*. The service decides something
needs a person, opens a pipe, and waits. The user's only power is to answer or
to cancel. Everything in this document inverts that: the user opens the tray,
looks at a list, and starts an operation.

That is not a bigger window. It is a different security question.

| | 0018 | This document |
|---|---|---|
| Who starts | The service, because a job reached it | The person, because they clicked |
| What the ACL protects | The right to answer a prompt | The right to **begin an operation** |
| Worst case if the ACL is wrong | Somebody answers a prompt meant for the user | Somebody starts a PIN change, an unblock, or a renewal |

The pipe is granted to `INTERACTIVE` and `LocalSystem` and to nothing else, and
that was already the right ACL — but it was carrying less weight. From here on
it is the only thing standing between *being logged in at this machine* and
*acting on the token in it*. That is a defensible boundary: physical presence
plus a session is what a PIN prompt assumes anyway. It should be a deliberate
choice rather than an inherited one.

**The UI never touches the card.** Every APDU stays in the service, which owns
the reader. The UI renders and asks; it holds no PC/SC handle, no PIN beyond
the moment it sends one, and no card state of its own. A tray application that
cached what it last saw would be a second source of truth that goes stale
exactly when it matters — when somebody pulls the token out.

## What the tray shows

One list, drawn from two sources, and the disagreement between them is the
interesting part.

| Column | From |
|---|---|
| Slot, subject, issuer, expiry | The card, read by the service |
| State — installed, expiring, stale, unknown to Blinky | The card compared against what the backend holds |

A certificate the backend thinks is installed and the card does not have is
precisely the leak that [02](02-data-model.md) separates `Issued` from
`Installed` to make visible, and precisely what happened on 20 August 2026 when
a token was reset outside Blinky. Showing both sides means the person holding
the token can see it before an operator does.

A slot holding a key with no certificate — the residue of an enrolment that
failed after generating — is shown as such. It is not an error, and it is not
nothing: it explains why a retry into that slot will be refused.

## The PIN dialog

Three operations share one layout, because they differ only in what the first
field means — and in one case whether there is a first field at all:

| Operation | First field | Card command |
|---|---|---|
| Change the PIN | Current PIN, filled in when the card says it is still the factory one | `CHANGE REFERENCE DATA` |
| Unblock, online | *nothing* — the PUK is not the user's to know | `RESET RETRY COUNTER`, then `CHANGE REFERENCE DATA` |
| Unblock, by telephone | The code an operator read back | the same two |

There is deliberately no "change the PUK". A PUK somebody chooses is written
down, shared, and identical across a drawer of tokens; a better one chosen by a
better-informed person is still all three. The value is Blinky's, and using it
replaces it.

Below that, always: **the new PIN twice**. The confirmation field is not
ceremony. A mistyped PIN that the card accepts is a token the user cannot open
and nobody can diagnose — the card has no idea anything went wrong, and the
next failure looks like a forgotten PIN eight hours later. Two boxes and a
comparison cost nothing and remove the entire failure mode.

The dialog must distinguish its refusals, because they call for different
actions from the person reading them:

- *The two entries do not match* — retype; nothing was sent anywhere.
- *This PIN is too simple* — the policy refused it; nothing was sent to the
  card, and **no attempt was consumed**.
- *The card refused the current PIN — N attempts remain* — the card answered
  `63CN`; an attempt is gone.

Collapsing these into "PIN change failed" would be the single most expensive
piece of laziness available here.

## Not a simple PIN

The rule lives in two places for one reason: **the PIN never leaves the
workstation, so the check cannot happen where the policy is kept.**

The policy travels, the PIN does not. The backend publishes the rules; the
service enforces them locally, before the first byte reaches the card. The
backend never sees the value it is setting rules about, and never will — see
[06](06-security.md).

Enforcement belongs in the **service**, not only in the window. The window is
where the rule is explained while the user types; the service is where it is
applied. A rule checked only in the UI is a rule that a second UI does not have.

What can actually be checked, honestly:

| Rule | Why |
|---|---|
| Length 6–8 | PIV. Shorter is not possible; longer is not storable |
| Not the default `123456` | The most common PIN on any PIV fleet is the one the factory set |
| Not a single repeated digit | `111111` |
| Not a straight run, either direction | `123456`, `654321` |
| Not the same as the PUK | Otherwise unblocking restores the PIN that was just rejected |
| Not the token's serial, whole or in part | It is printed on the object the PIN protects |

What cannot be checked, and should not be implied: birthdays, names, anything
in a dictionary, anything the user has used elsewhere. A policy screen that
lists six rules invites the belief that a PIN passing them is a good PIN. It is
a PIN that is not obviously bad.

**Digits only, by default.** SP 800-73 allows more, and a YubiKey accepts more,
but the PIN gets padded to eight bytes and read back by software written by
people who assumed digits. A non-numeric PIN works until the day something else
touches the card. Allowing more should be a deployment setting with that
sentence next to it.

## Unblocking

The PUK is escrowed. Unblocking from a workstation means it has to come back to
one, and that is the only genuinely new exposure in this document.

The shape that keeps it bounded:

1. The person asks from the tray. That is a **request**, not an authorization.
2. The backend decides. This is a disclosure of an escrowed secret and is
   audited as one, exempt from retention like every other PUK disclosure.
3. The PUK travels once, over mTLS, to the service — never to the UI, never to
   disk, never into a job payload that the database would keep.
4. The service unblocks, then **rotates the PUK immediately** and escrows the
   new one. A disclosed PUK is spent.

Where `puk_state` is `Disabled` or `NotApplicable`, the action is **absent from
the tray**, not shown and then failed. The Bio has no PUK by design; offering
an unblock on it and reporting an error afterwards teaches people that the UI
guesses.

**Open, and a policy question rather than a technical one:** whether a user may
unblock their own token without an operator. It turns "I forgot my PIN" into
self-service, which is either the point or the hole, depending on whose fleet
it is. The default is operator-approved, because that is the choice that can be
loosened later without a migration.

## Unblocking with no network

The workstation is offline. The person answering the telephone is not.

1. The agent shows a **challenge** — the token's serial and a random number,
   sixteen characters in Crockford's base32, grouped in fours.
2. Somebody reads it out. An operator types it into the console.
3. The server answers with a **response**, fourteen characters, and reads it
   back down the line.
4. The agent unblocks with it, then rotates the PUK.

**The response carries the PUK, and no design avoids that.** The card needs the
PUK bytes and an offline machine has no other way to learn them. The
alternative — a derivation secret on every workstation — trades a value spoken
once for a value that lets any compromised laptop unblock any token unaided.
That is the worse trade, and saying so plainly is better than a scheme that
looks like it hides the PUK and does not.

What makes the spoken value harmless is that it is **spent**. Both sides derive
the replacement from the response and the challenge together:

    next = HMAC-SHA256(currentPuk, "blinky-puk-rotation|" + challenge)[0..8] as digits

The server derives it when it reads the code out; the agent derives it when the
card accepts it. Neither tells the other, which is the only reason this works
with no network — and the code that was spoken opens nothing from the moment
the card takes the new value.

### Why the codes are not eight bare digits

A check character. A PIN unblock has three PUK attempts behind it, and a
mistyped code sent to the card spends one of them; caught in the agent it costs
a "read that back to me". The alphabet has no `I`, `L`, `O` or `U`, and
decoding folds those onto `1` and `0`, because somebody will type what they
think they heard. The check is position-weighted so that two characters
transposed — the second most common mistake — do not produce the same one.

Verified on hardware on 20 August 2026: two full cycles on one token, the
second using a PUK the two sides derived separately and never exchanged, and a
deliberately mistyped code refused with the card's attempt counter untouched at
3/3.

### What is left ragged, on purpose

An offline unblock that fails **at the card** cannot say so — that is what
offline means. The server has already rotated its side, so the next code read
out would be refused as well. The way back is a person saying "that code did
not work", which is `POST /api/tokens/puk/refused` and, later, a button in the
console. Automating it is not possible; the machine that knows is the one that
cannot call.

### What none of this does

Establish that the helpdesk is talking to the right person. That is a process
control, and a challenge on a screen does not become one by being cryptographic.

## Renewal

The user's click is a request. The backend decides whether a credential may be
renewed, and issues a job like any other — the workstation does not get to
authorize its own certificates.

Renewal generates a new key in the slot, which **destroys the old one**. The
ordering is therefore not negotiable:

1. Generate, attest, sign, issue and write the new certificate.
2. Confirm it is on the card by reading it back.
3. Only then supersede and revoke the old credential.

Reversed, a failure between the two steps leaves the person holding a token
with no working credential and a revoked one behind them. `supersedes_id` links
them so the history survives ([02](02-data-model.md)).

This is also the one place where the agent's "this slot already holds a key,
refusing to destroy it" guard must be **explicitly** lifted, by a job that says
it is a renewal. Lifting it generally would remove the guard; leaving it in
place would make renewal impossible. Neither is acceptable, so the job carries
the intent.

## The tray itself

- Starts per user session at logon, one instance.
- Shows the window on demand, and raises it when the service prompts — the
  0018 path stays exactly as it is.
- The icon reflects reader state and nothing more interesting than that: token
  present, token absent, something expiring soon.
- No card state cached between openings. Every view is a fresh read, because
  the token can leave the machine between two glances at the same window.

## What this does not do

- It does not make the workstation an authority. Every issuance decision stays
  on the server, verified against the server's own pinned attestation root.
- It does not show other people's tokens. The tray sees the readers on this
  machine.
- It does not replace the console. An operator acting on somebody else's token
  is Phase 5.
