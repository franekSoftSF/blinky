# 11 — Enrolment from the console

The second half of patch **0052**. The first half landed as
`5c48bda 0052: wire console to credential recycle jobs`: the console can
recycle a credential, and cannot create one.

This is written because the gap is not in the console. Enrolling a token needs
four things — a serial, a slot, a profile and a person — and the API today
offers the console **none of the last three**. A page built against what
exists would have to ask an operator to type a SID by hand, and
[the issuance service](../src/Blinky.Api/Credentials/CredentialIssuanceService.cs)
says plainly why that is the wrong answer:

> The tempting fix — put a plausible SID in and move on — produces a
> certificate that asserts an identity nobody issued.

So: the API side first, the page against it.

## What issuing needs today

`POST /api/jobs/enrol` already exists and works. It takes

```json
{
  "tokenSerial": 23673995,
  "slotId": "9A",
  "profileName": "smartcard-logon",
  "displayName": "Admin",
  "upn": "Admin@blinky.lab",
  "objectSid": "S-1-5-21-300962399-1684673814-2484441606-1104",
  "reason": null
}
```

behind an `X-Blinky-Operator` header. Every one of those values is currently
found by hand — `samba-tool user show` for the SID, the source for the profile
names, [PivSlot.cs](../src/Blinky.Piv/PivSlot.cs) for the slot spelling. That
is the whole problem.

## Backend — five gaps

These are API work, not console work.

### 1. Profiles are invisible

`Profiles` is a static class with two constants. Nothing enumerates it, so a
console dropdown would be a hardcoded copy that drifts. It also carries a rule
the UI has to know: `smartcard-logon` refuses without an `objectSid`, and a
page that offers the profile without knowing that produces a job that fails a
minute later for a reason the operator cannot see.

```
GET /api/profiles
[ { "name": "smartcard-logon", "requiresObjectSid": true,  "requiresUpn": true,
    "keyAlgorithm": "ECCP256", "days": 365,
    "extendedKeyUsage": ["Client Authentication", "Smart Card Logon"] },
  { "name": "client-auth",     "requiresObjectSid": false, "requiresUpn": false, ... } ]
```

Patch 0022's open half is the same list moving into the database. This endpoint
should be written so that move does not change its shape.

### 2. Nothing exposes cardholders

[`Cardholder`](../src/Blinky.Domain/Entities/Cardholder.cs) exists, is mapped,
holds `DisplayName`, `Upn`, `ObjectSid`, `DistinguishedName` and
`DirectorySource` — and has no endpoint of any kind. `Job.CardholderId` exists
and is never set by the enrolment route.

The entity's own comment says the SID is *"resolved at onboarding rather than
at issuance"*, which is the design. Onboarding is the thing that does not
exist.

```
GET  /api/cardholders?q=admin
POST /api/cardholders     { displayName, upn, objectSid, distinguishedName? }
```

`POST` should reject a malformed SID (`S-1-5-21-` and four sub-authorities) at
the boundary rather than storing a string that fails at issuance.

### 3. Enrolment should take a cardholder, not three loose strings

Keep the current shape working — the smoke path and any script depend on it —
and accept `cardholderId` as an alternative. When given, `displayName`, `upn`
and `objectSid` come from the row, and `Job.CardholderId` is finally set, which
is what makes a credential traceable to a person afterwards.

### 4. A failed job says nothing

`/api/console/overview` projects jobs as

```csharp
j.Id, type, state, j.TokenSerial, j.Attempt, j.CreatedAt
```

`Job.Result` is right there and is not included. So the console can show
`Failed` and cannot show why — and the failures worth showing are exactly the
ones an operator can fix: a wrong PIN, a slot that already holds a key, a token
still on its factory management key. One field, and the page becomes usable.

Include `Result` and `UpdatedAt`.

### 5. There is no directory lookup

The proper fix behind gap 2: an LDAP client that resolves a name to a UPN and a
SID, so nobody types either. The API has **no LDAP dependency at all** today —
`DirectorySource` is an enum with nothing behind it.

Deliberately last. Onboarding by hand is unpleasant with ten people and
impossible with a thousand, but it is correct at both, and it unblocks the
console now. The lookup then fills the same table rather than replacing it.

## Console — the page

Frontend work, against the endpoints above.

**Where.** The token row in `inventory.ts` already shows slots and their
management state. Enrolment belongs on an empty or unmanaged slot of a token
whose agent is online — not as a free-standing form, because three of the four
values are already known from where the operator clicked.

**The dialog.**

- Slot — prefilled from the row, `9A` spelled as in `PivSlot`.
- Profile — from `GET /api/profiles`.
- Person — search `GET /api/cardholders?q=`, with an inline "add someone" that
  posts to `POST /api/cardholders`. An operator with a fresh directory should
  not have to leave the dialog.
- Confirm shows exactly what will be asserted: the UPN and the SID, spelled
  out. This is a logon credential; the operator should see the identity it will
  claim before it is claimed.

**When the profile requires a SID and the chosen person has none**, refuse in
the dialog with that sentence. Do not post a job that the server will refuse —
the server's refusal is correct and arrives too far from the click.

**After posting**, follow the job. The state is already in the overview
snapshot the store polls; with gap 4 fixed, a failure shows its reason. Live
per-step progress is the other half of 0052's definition of done and can come
after this: a job that reaches `Installed` is the gate here.

**`AwaitingUser` is not a failure.** It means the token is waiting for a PIN or
a finger at the workstation, and it can sit there for a minute. It needs its
own wording and its own colour, or every enrolment will look stuck.

## Done when

An operator opens the console, picks an empty slot on a token an agent can
see, chooses `smartcard-logon`, searches for a person, confirms, and watches
the job reach `Installed` — without a terminal, and without anybody typing a
SID into a JSON body. A profile that needs a SID against a person who has none
is refused in the dialog, in words.

## The help-desk screen

Added 22 August 2026, after a screenshot of a commercial CMS's help-desk view.
The shape is not the interesting part, and getting it wrong costs the console a
rewrite — so it is copied deliberately.

**`GET /api/tokens/{serial}/helpdesk`** answers the whole screen in one call.
A person on a telephone should not be assembling it from four requests while
somebody waits. It returns:

- `cardholder` — who holds it, or `null`. Null rather than an empty person.
- `device` — serial, state, firmware, form factor, attestation thumbprint,
  when it was last seen, and `manageable`: false once the management key is
  `Lost`, because every write needs it and the console should grey the actions
  out rather than offer ones that fail at the card.
- `pin`, `puk`, `biometric` — each with its state and its retries left, the way
  a card holds them: applications with policies, not properties of the device.
  `puk.unblockable` is false when the PUK is itself blocked, deleted or absent.
- `slots` — what is physically in each one.
- `credentials` — serial, subject, issuer, validity, revocation, and `expired`
  worked out here rather than in a browser from two dates and a clock nobody
  trusts.

**`POST /api/credentials/{id}/suspend`** puts one credential on hold. Distinct
from blocking the token: a card with two credentials can have one suspended
while the other keeps working, which is what "suspend this application" means
on that screen. Hold is the only revocation reason X.509 allows to be taken
back, which is what makes this reversible and the rest of the actions
permanent — the response says `reversible` rather than leaving it to be
discovered.

### The actions on that screen, and where they are

| On the screen | Endpoint |
|---|---|
| Terminate | `POST /api/tokens/{serial}/block` with `Terminated` |
| Hold | the same, with `Suspended` — and `unblock` lifts it |
| Suspend (one application) | `POST /api/credentials/{id}/suspend` |
| Revoke (one application) | `POST /api/credentials/{id}/revoke` |
| Create Unlock Request | `POST /api/tokens/{serial}/puk/checkout`, or `offline-unblock` for a workstation with no network |
| Replace, Request Re-Issuance | `POST /api/jobs/enrol` with a new `reason` |
| Request Applications Update | `POST /api/jobs/inventory` |

### Two that are deliberately missing

**View Certificate.** The database holds the serial number, subject, issuer and
validity — not the certificate. Nothing stored it, because until now nothing
needed it. Showing one means either keeping the issued certificate (a column, a
migration, and the honest answer) or fetching it from the card through the
agent, which needs the card to be present to look at a record. The first is
right and is not done yet.

**Get Initial PIN.** Not missing by accident and not coming. The commercial
product generates the first PIN centrally and shows it to a help desk, which
means it existed on a server, in a database, and on somebody's screen. This
project's rule is older than this screen: a PIN is typed by the person who owns
it, into a window the service cannot draw, and is never stored, never logged
and never carried in a job. A card is issued with the PIN unset and the holder
sets it; if that is unacceptable for some deployment, the thing to change is
the deployment.

## The directory

Gaps 2 and 5, written 22 August 2026.

**LDAP, not a Windows connector.** Samba4 and Windows AD answer the same LDAP
with the same attributes for everything read here — display name, account name,
UPN, `objectSid`, DN — so one implementation serves both and the configured
`DirectorySource` is a label for the record rather than a branch in the code. A
Windows-native connector earns its place where LDAP falls short, not because
the directory happens to run on Windows.

**Read-only, and that is the point.** Nothing writes to the directory.
Publishing into `userCertificate` or touching `altSecurityIdentities` is a
different privilege and a different decision — so the account this binds as
needs nothing but read, which is an easy thing to ask a directory
administrator for and an easy thing to audit. Leave the bind DN empty to bind
with Kerberos from the container's own credentials instead: better still,
because then there is no password anywhere.

```
GET  /api/directory/users?q=admin
GET  /api/cardholders?q=admin
POST /api/cardholders   { "directoryAccount": "admin" }
POST /api/cardholders   { "displayName": "...", "upn": "...", "objectSid": "..." }
```

Both search endpoints return **`issuable`** per person: true only when they are
enabled and hold both a UPN and a SID. The console should grey the choice out
rather than posting a job the issuance service will refuse — the refusal is
correct and arrives too far from the click.

`POST /api/cardholders` with a `directoryAccount` takes everything from the
directory and **ignores** anything else the caller sent, rather than merging:
half a person from each source is the worst of both. An account that matches
more than one person is refused rather than resolved — picking the first would
issue a logon credential to whoever the server happened to return first.

A SID that is typed rather than read is checked at the boundary. Stored, it
fails at a logon three weeks later, and the message then is about trust rather
than about a field somebody mistyped.

### Not configured

The endpoints exist and answer `501` with "no directory is configured" rather
than an empty list. "Nobody matched" and "there is nowhere to look" are
different answers, and the console should be able to tell an operator which one
it got. A deployment with no directory is a normal deployment: cardholders are
entered by hand and `DirectorySource.Local` says so.
