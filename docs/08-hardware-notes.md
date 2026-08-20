# 08 — What the hardware changed

Every rule in this project that came from a measurement rather than from
reading, and where it now lives.

This is an index, not a second copy. The reasoning stays in the document that
uses it; what is here is the finding, the evidence, and the pointer — so that a
reader can tell which decisions were reasoned and which were forced, and so
that nobody quietly "simplifies" one of them back into the bug it came from.

The bench: YubiKey 5.4.3, 5.7.1 and 5.7.2 Bio Multi-protocol, a second 5.4.3, an
HID Crescendo Key V3, an HID C4000, an OMNIKEY 5022 reader, and a Windows Hello
virtual reader — with HID ActivClient installed alongside.

## The tokens

| Finding | Evidence | Where it lives |
|---|---|---|
| The management key is **3DES below firmware 5.7 and AES-192 from 5.7**, so the algorithm must be read, never derived from the version | Two independent 5.7 devices reported AES-192, a 5.4.3 reported 3DES, all three still at the factory value | [03 § Management key](03-piv-layer.md#management-key) |
| A **Bio Multi-protocol has no PUK at all**, by design. Any other token without one has had its recovery path removed | `GET METADATA 81` returned zero *total* retries on the Bio and three on the others | [02 § Secrets at rest](02-data-model.md#secrets-at-rest), `TokenClassification.Puk` |
| Metadata tag `06` is **two bytes in the PIN slot and one byte in slot 96** | PIN slot returned `06 02 08 08`; the biometric slot returned `06 01 03` | [03 § Biometric verification](03-piv-layer.md) |
| The **attestation intermediate is different on every device**, so only the root can be pinned | Three tokens produced three `CN=Yubico PIV Attestation` certificates with three different serials, all under one root | [04](04-pki-backends.md), `AttestationVerifier` |
| Attestation extensions live under **`1.3.6.1.4.1.41482.3`**, not `.13`, and the numbers within it are 3, 7, 8, 9 | The verifier rejected a genuine token as "not an attestation" until the arc was corrected | [03 § Enrolment](03-piv-layer.md#enrolment-end-to-end) |
| **`GENERATE ASYMMETRIC KEY PAIR` (`47`) is standard PIV**, not a Yubico extension | Sent to five cards with an invalid algorithm identifier so nothing could be generated: all five answered `6982`. The control, undefined `INS 4E`, answered `6D00` on all five | [03](03-piv-layer.md), `tools/InsProbe` |
| **`6D00` means absence, not failure** | `ATTEST` on a card from another vendor returned it and threw, wrecking an inventory pass over four unrelated tokens | [03 § Cards that are not YubiKeys](03-piv-layer.md), `PivSession.Attest` |
| The **form factor exists only inside an attestation** | Blank on three of four tokens, present on the one holding a key. Reading it from a model name would have filled the column with a guess | `InventoryCollector` |
| A PIV card with no serial **vanished silently** from the agent's view | An HID Crescendo produced no report at all; an operator cannot tell that from a dead agent | [03](03-piv-layer.md), `UnsupportedCardReport` |
| **A blocked PIN and a token with no PUK are different situations**, not one "cannot get in" flag | Three deliberate wrong attempts left `Blocked`, 0 retries and `puk_state=Default`; the factory PUK restored it to 3/3 | `TokenClassification`, [07 § Phase gate](07-roadmap.md) |
| **.NET refuses the PIV factory 3DES management key outright** | `TripleDES.Key` throws "known weak key": the factory value is the same eight bytes three times, a degenerate 3DES key. Every pre-5.7 token at its factory value is unreachable through the obvious API | `ManagementKey.TripleDesEde` |
| The installed **minidriver does not contend at the PC/SC layer, and does claim the card at the CSP layer** | Transactions acquire cleanly with HID ActivClient present — but `certutil -scinfo` reports the YubiKey as `Card: HID ActivClient (YubiKey 5)`, and a certificate written into a PIV slot does not reach the user's certificate store | [03 § Transport](03-piv-layer.md#transport), [09](09-lab.md) |
| **Outbound command chaining works** | A 1019-byte certificate object written to a slot and read back identical — more than one APDU of data, so `CLA 0x10` ran for real | `PivConnection`, `tools/IssueOnCard` |
| **Virtual readers appear in the list** and answer `SELECT PIV` with `6A82` | Windows Hello for Business, on every machine that has it enabled | `PivSession.Select` |

## The stack

| Finding | Evidence | Where it lives |
|---|---|---|
| **`pathlen` counts what follows, so a two-tier root needs `pathlen:1`**, not `0` | Doc 04 said the opposite. A root with `pathlen:0` rejected every chain through its own issuing CA, reporting "basic constraints not satisfied" — which points at the leaf | [04 § Path length](04-pki-backends.md), `scripts/new-ca.sh` |
| **`jsonb` needs a typed parameter**, not just a column type | The schema validated and the first insert failed with `42804: column "payload" is of type jsonb but expression is of type text` | `JsonbType`, `tools/SchemaTool --roundtrip` |
| **A CRS in blocking mode eats our own protocol** | The same SQL injection returns 403 on the console listener and is logged with `is_interrupted:false` on the agent listener | [01 § The edge](01-architecture.md), [06](06-security.md) |
| **`ssl_verify_client on` refuses enrolment before it can happen** | The one endpoint an agent must reach without a certificate never got past the handshake | [05 § Agent enrolment](05-agent-protocol.md#agent-enrolment) |
| **A job's envelope and its row must carry the same identifier** | They did not: the endpoint generated one and NHibernate assigned another. The agent reported progress against a job that did not exist, the server refused it, the agent ignored the refusal — so the work ran, nothing was recorded, and the watchdog reclaimed the job | `JobService.Create`, `BackendClient` |
| A **bootstrap token cannot be single-use** if it ships in an MSI to a fleet | Design review against the actual deployment path | [05](05-agent-protocol.md#agent-enrolment) |

## Windows, for anyone contributing from one

Neither of these is about Blinky, and both cost an afternoon.

- **Git Bash rewrites anything that looks like a path.** `openssl req -subj
  /CN=localhost` arrives as `C:/Program Files/Git/CN=localhost`. Fixed with
  `MSYS_NO_PATHCONV=1` in `scripts/dev-certs.sh`.
- **Windows `curl` is built against Schannel** and cannot load a PEM client
  certificate, so mTLS checks fail for a reason that has nothing to do with the
  code under test. `smoke-test.sh` drives curl from a container instead, which
  also tests from the compose network rather than the host.

## The method, which is the actual lesson

Eight of the token findings above are the same mistake in different clothes:
**something was inferred that could have been asked.**

Reader names, firmware numbers, and the model printed on the plastic are
strings. The card knows whether it does biometrics, which management-key
algorithm it holds, whether it has a PUK, and whether it understands an
instruction — and it will say so. Every time this project inferred instead of
asking, the hardware corrected it, usually by producing a plausible wrong
answer rather than an obvious failure.

The `INS 47` measurement is the shape to copy: send the question, **send a
control whose answer you already know**, and compare. Without the undefined
`INS 4E` returning `6D00`, the `6982` from `INS 47` would only have meant "not
`6D00`" — which is not the same as "understood".
