# 03 — PIV layer

`Blinky.Piv` talks to the token over PC/SC and speaks PIV APDUs directly. No
minidriver, no PKCS#11 module, no CLI wrapper.

## Why raw APDUs

The three realistic options, and why this one:

| Approach | Verdict |
|---|---|
| **PC/SC + PIV APDUs** | Chosen. One NuGet dependency for the transport, everything else is our code. Works on Windows and Linux from the same binary. Full access to key generation, attestation, metadata, management-key rotation and PIN retry counters — the operations a CMS exists to perform. |
| **PKCS#11 (`ykcs11`)** | Rejected. Requires shipping and versioning a native library to every workstation, and the interesting administrative operations sit outside the PKCS#11 model anyway, so half the code would be APDUs regardless. |
| **`ykman` / `yubico-piv-tool`** | Rejected. Parsing another tool's console output, a hard dependency on its version and install path, and PINs in `argv` where any user on the box can read them. Useful as a test oracle, never in the product path. |

The cost is honest: PIV is an ISO 7816 protocol with Yubico extensions, and this
document exists because that cost has to be paid in knowledge somewhere.

## Transport

`PCSC-sharp` for `SCardEstablishContext` / `SCardConnect` / `SCardTransmit`
(P/Invoke to `winscard.dll` on Windows, `libpcsclite` on Linux). Everything
above it is ours.

Three rules the transport layer enforces:

1. **Connect shared, work in a transaction.** `SCARD_SHARE_SHARED` with an
   explicit `BeginTransaction`/`EndTransaction` around every multi-APDU
   sequence. Exclusive mode fights the Windows Smart Card service and the
   YubiKey minidriver if one is installed; a transaction gets the same atomicity
   without taking the card away from the OS.
2. **One session per operation, re-select every time.** The PIV applet's
   security state (verified PIN, authenticated management key) is tied to the
   session and must be treated as lost after any reset, removal or timeout.
   Nothing caches "we are already authenticated".
3. **Chain long commands.** An RSA-2048 certificate does not fit in a short
   APDU. The layer uses command chaining (`CLA 0x10` on all but the last block)
   rather than extended-length APDUs, because some readers and virtual-reader
   stacks handle extended length badly and chaining always works.

Prerequisite on the token itself: the **CCID interface must be enabled**
(`ykman config usb`). A YubiKey shipped with CCID disabled is invisible to
PC/SC, and the error the user sees is "no reader", which sends everybody
looking in the wrong place.

## Applet and slots

```
SELECT  00 A4 04 00  05  A0 00 00 03 08
```

| Slot | PIV name | Data object | Blinky uses it for |
|---|---|---|---|
| `9A` | PIV Authentication | `5FC105` | Smart-card logon, the primary credential |
| `9C` | Digital Signature | `5FC10A` | Signing. PIN policy `Always` by definition |
| `9D` | Key Management | `5FC10B` | Encryption / S-MIME decryption |
| `9E` | Card Authentication | `5FC101` | Physical access, no PIN |
| `82`–`95` | Retired key management | `5FC10D`–`5FC120` | Old `9D` keys kept so historic mail still decrypts |
| `F9` | Attestation | — | Read-only. The token's proof of itself |

Retired slots are in the data model from the start because rolling a `9D` key
without keeping the old one destroys the user's mail archive, and discovering
that after the fact is not recoverable.

## The commands that matter

Standard PIV:

| INS | Command | Note |
|---|---|---|
| `A4` | SELECT | |
| `20` | VERIFY | `P2=0x80` for the PIN. `P1=0xFF` resets the verified state |
| `24` | CHANGE REFERENCE DATA | PIN and PUK change |
| `2C` | RESET RETRY COUNTER | PIN unblock using the PUK |
| `87` | GENERAL AUTHENTICATE | Sign, decrypt, and management-key mutual auth |
| `CB` | GET DATA | Read a data object, tag `5C` |
| `DB` | PUT DATA | Write a data object — this is how a certificate gets onto the card |

Yubico extensions — the ones that make a CMS possible:

| INS | Command | Note |
|---|---|---|
| `47` | GENERATE ASYMMETRIC KEY PAIR | `P2` = slot. Returns the public key; the private key never exists off-card |
| `F9` | ATTEST | `P1` = slot. Returns an X.509 certificate for the key in that slot |
| `F7` | GET METADATA | Firmware 5.3+. PIN/touch policy, key algorithm, whether the management key is default |
| `F8` | GET SERIAL | |
| `FD` | GET VERSION | Firmware version |
| `FF` | SET MANAGEMENT KEY | `P2=0xFF` normal, `0xFE` requires touch |
| `FA` | SET PIN RETRIES | Resets PIN *and* PUK to defaults as a side effect — see below |
| `FB` | RESET | Wipes the PIV application. Only accepted when PIN *and* PUK are blocked |

`GET METADATA` is worth calling out: before firmware 5.3 there is no way to ask
the card what its own PIN policy or management-key state is, so on older tokens
Blinky records `Unknown` rather than guessing. The data model has that state for
exactly this reason.

`SET PIN RETRIES` resetting the PIN and PUK to factory defaults is the kind of
detail that produces a support incident once and then never again. It is called
during personalisation, before the PIN and PUK are set — never after.

## Algorithm identifiers

```
0x06  RSA-1024      (refuse: below policy)
0x07  RSA-2048
0x11  ECC P-256
0x14  ECC P-384
```

Firmware 5.7 adds `0x05` RSA-3072, `0x16` RSA-4096, `0xE0` Ed25519 and `0xE1`
X25519. Blinky reads the firmware version first and offers a profile only if the
token can execute it, because the alternative is a key-generation failure
several steps into a user-facing workflow.

Ed25519 is available on the token but **not** usable for Windows smart-card
logon; the profile validator rejects that combination rather than issuing a
certificate that cannot be used.

## Enrolment, end to end

```
 Agent                          Token                     Api / Worker
   │  SELECT PIV                  │                          │
   ├─────────────────────────────►│                          │
   │  GET VERSION / SERIAL        │                          │
   ├─────────────────────────────►│                          │
   │  authenticate mgmt key (87)  │                          │
   ├─────────────────────────────►│                          │
   │  GENERATE KEY PAIR (47)      │                          │
   ├─────────────────────────────►│                          │
   │◄──── public key ─────────────┤                          │
   │  ATTEST slot (F9)            │                          │
   ├─────────────────────────────►│                          │
   │◄──── attestation cert ───────┤                          │
   │  VERIFY PIN (20)             │                          │
   ├─────────────────────────────►│                          │
   │  sign CSR TBS (87)  ── blinks if touch policy set        │
   ├─────────────────────────────►│                          │
   │◄──── signature ──────────────┤                          │
   │                              │   PKCS#10 + attestation  │
   ├──────────────────────────────┼─────────────────────────►│
   │                              │                          │ verify chain,
   │                              │                          │ call CA
   │◄─────────────────────────────┼──── certificate ─────────┤
   │  PUT DATA 5FC1xx (DB)        │                          │
   ├─────────────────────────────►│                          │
   │                              │   installed              │
   ├──────────────────────────────┼─────────────────────────►│
```

The CSR is assembled on the agent and **signed by the card**: Blinky builds the
`CertificationRequestInfo`, sends its digest to slot `9A` via GENERAL
AUTHENTICATE, and wraps the returned signature. That is what makes the PKCS#10 a
genuine proof of possession rather than a formality.

Attestation is verified before the CA is called, not after. The chain is
`slot cert → F9 attestation cert → Yubico PIV Attestation CA → Yubico PIV Root
CA`, and the checks are:

- the chain terminates in the pinned Yubico root,
- the attested public key equals the key in the CSR,
- the serial in extension `1.3.6.1.4.1.41482.13.2` equals the token being
  enrolled,
- the PIN and touch policy in `1.3.6.1.4.1.41482.13.3` satisfy the profile,
- firmware `1.3.6.1.4.1.41482.13.1` and form factor `…13.4` are recorded.

If any of that fails, no request reaches the CA. A CMS that signs first and
verifies later is a CMS that will eventually certify a software key.

## Management key

Two facts that have to be handled together:

- Firmware before 5.7 ships a **3DES** management key, default
  `010203040506070801020304050607080102030405060708`.
- Firmware 5.7 and later ships **AES-192**, same byte pattern.

So the agent does not assume. It reads `GET METADATA` where available, and
otherwise attempts authentication with the algorithm implied by the firmware
version, falling back once. Algorithm identifiers for the key itself:
`0x03` 3DES, `0x08` AES-128, `0x0A` AES-192, `0x0C` AES-256.

Authentication is a three-step mutual challenge over GENERAL AUTHENTICATE using
tag `0x7C` with `0x80` witness, `0x81` challenge and `0x82` response. Mutual —
both sides prove knowledge — which is what allows the agent to detect a swapped
or emulated card before writing anything to it.

Personalisation replaces the default with the derived value from
[02 — Data model](02-data-model.md#secrets-at-rest) and sets
`mgmt_key_state = Diversified`. Blinky refuses to issue onto a token still
holding the factory key, and says so in those words.

## Touch, and why it needs its own state

With touch policy `Always` or `Cached`, the signing APDU does not return. The
token blinks and waits for a finger, then either completes or times out.

For the agent this means an APDU that blocks for up to fifteen seconds is
*normal*, not a hang. The executor moves the job to `AwaitingUser`, tells
`Agent.Ui` to raise the "touch your key" prompt, and applies a separate,
longer deadline. Without that distinction the watchdog would reap every job on
a touch-policy profile.

`Cached` gives one touch fifteen seconds of validity, which is why
personalisation batches its touch-requiring operations together.

## Error map

| SW | Meaning | Blinky's response |
|---|---|---|
| `9000` | Success | |
| `61xx` | More data available | GET RESPONSE, continue |
| `63Cx` | PIN verification failed, `x` retries left | Surface the exact count to the user; update `pin_retries_left` |
| `6982` | Security status not satisfied | PIN or management key not authenticated — a bug in our sequencing, log it as such |
| `6983` | Authentication method blocked | PIN or PUK blocked. Route to the unblock workflow |
| `6A80` | Incorrect parameters in data field | Malformed APDU. Ours to fix, never the user's |
| `6A82` | File or object not found | Empty slot. Expected during inventory |
| `6A88` | Referenced data not found | Slot has no key. Expected before generation |
| `6D00` | Instruction not supported | Firmware too old for a Yubico extension. Degrade, do not fail |

Every failure records the SW verbatim in the job result. "Enrolment failed" with
no status word is not a diagnosis, and this is a system whose failures happen on
someone else's desk.

## Testing without a token in every CI runner

- **Unit tests** run against a recorded-APDU fake: a scripted
  request/response transcript captured from real hardware. Covers parsing,
  chaining, error mapping and the enrolment sequence.
- **Integration tests** run against `vsmartcard`/`vpcd` with a PIV emulator for
  the standard commands. The Yubico extensions are not emulated, so attestation
  and metadata paths are hardware-gated.
- **Hardware tests** need a real YubiKey 5 and are a tagged suite that runs on
  one machine. Anything touching the management key, attestation, or `RESET` is
  in that suite by definition.

`yubico-piv-tool` is installed on the hardware test machine as an independent
oracle — if Blinky and it disagree about what is on the card, Blinky is wrong
until proven otherwise.

## Windows-specific notes

- After writing a certificate the Windows certificate propagation service must
  re-read the card before the credential appears in the user's store. The agent
  triggers a re-read rather than telling the user to unplug and replug.
- If the YubiKey minidriver is installed, the smart card resource manager holds
  the card between operations. Transactions handle it; exclusive connections do
  not.
- The agent runs as LocalSystem and has its own PC/SC context. This is fine — it
  is a *different* context from the logged-in user's, not a shared one, which is
  another reason PIN entry lives in `Agent.Ui` and not in the service.
