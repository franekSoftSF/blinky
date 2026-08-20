# Fixtures

Two real APDU captures, both recorded by `tools/PivProbe` against hardware on
2026-08-20. The format is what the probe writes, so a fresh capture can be
dropped in as-is:

```json
[ { "Label": "...", "Command": "00A4...", "Response": "6111...", "Sw": "9000" } ]
```

## `piv-inventory.transcript.json`

Three YubiKeys and one virtual reader, read back to back:

| Firmware | Management key | Notable |
|---|---|---|
| 5.4.3 | 3DES | the pre-5.7 side of the management-key split |
| 5.7.1 | AES-192 | factory defaults throughout |
| 5.7.2 | AES-192 | Bio Multi-protocol: fingerprints enrolled, no PUK |
| — | — | Windows Hello virtual reader, answers SELECT PIV with `6A82` |

All four PIV slots are empty on all three tokens, so this capture is about
identity, credential state and biometrics.

## `piv-provisioned.transcript.json`

One 5.7.1 with an ECC P-256 key and a self-signed certificate written into slot
`9A` by `ykman`. It covers what blank tokens cannot: reading a certificate off
a card, the slot metadata that goes with it, and **`61xx` response chaining on
real hardware** — a PIV data object holding even a P-256 certificate does not
fit in one APDU.

## What is removed, and what that guards against

**Serial numbers are replaced** with `00BADA55` and up, in order of first
appearance within each capture. The two files number independently, so the same
placeholder means different tokens in each.

**Attestation is not recorded at all.** An attestation certificate carries the
device's real serial in extension `1.3.6.1.4.1.41482.3.7` and identifies one
physical token. The probe stops recording around the ATTEST call rather than
filtering it out afterwards — the first attempt did filter, missed the
`GET RESPONSE` continuations, and put two thirds of a certificate into a file
headed for a commit. `FixtureSafetyTests` fails if either slips back in.

Patch 0012 needs attestation fixtures and will build a synthetic chain for
them.

## What these captures do not cover

Neither contains `6Cxx`, which comes from T=0 readers, and neither exercises
outbound command chaining, which needs a write. Both are covered by hand-built
cases in `PivConnectionTests`. A replay test alone would report green coverage
of code paths no card has ever taken.
