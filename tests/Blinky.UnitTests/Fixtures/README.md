# Fixtures

`piv-inventory.transcript.json` is a real APDU capture, recorded by
`tools/PivProbe` against three YubiKeys on 2026-08-19: a 5.4.3 with a 3DES
management key, a 5.7.1 with AES-192, and a 5.7.2 Bio Multi-protocol with no
PUK. It is the read-only inventory sequence, so nothing in it writes to a card.

**Serial numbers are replaced.** The `GET SERIAL` responses carry `00BADA55`
and friends rather than the real values; every other byte is exactly what the
cards returned. Nothing else in the capture identifies a device — all four PIV
slots were empty on all three tokens, so there are no certificates in it.

The format is what the probe writes, so a fresh capture can be dropped in as-is:

```json
[ { "Label": "...", "Command": "00A4...", "Response": "6111...", "Sw": "9000" } ]
```

## What this fixture does not cover

The capture contains `9000`, `63Cx`, `6A80`, `6A82` and `6A88` — and no
`61xx` at all, because every response fitted in one APDU over T=1. Chaining,
`6Cxx` and the remaining status words are covered by hand-built cases in
`PivConnectionTests` and `PivStatusTests`. A replay test alone would report
green coverage of code paths the hardware never exercised.
