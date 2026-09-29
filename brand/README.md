# The Blinky CMS mark

Sources are here, as SVG. Everything else — PNG, ICO, favicon — is generated
from them and committed next to the places that use it:

```bash
cd brand
npm install --no-save sharp@0.35.4
node build-assets.mjs
```

| File | What it is | Where it goes |
|---|---|---|
| `blinkycms-mark.svg` | the mark: a key in a cyan arc with a node at each end, on a dark tile | console sidebar and sign-in, `icon-512.png`, the `.ico` files at 64 px and above |
| `blinkycms-favicon.svg` | the mark simplified for 16–48 px — no arc, no nodes, no glow, which at that size are a cyan smudge | `favicon.svg`, `favicon.ico`, the tray icon, the small `.ico` entries |
| `blinkycms-logo.svg` | mark + „Blinky**CMS**” + the line from the README | `blinkycms-logo.png` for the README (GitHub will not load a mark an `<img>`'d SVG refers to) |

## One family, two products

The geometry is [BlinkyLite](../../BlinkyLite/brand/README.md)'s, deliberately
and without redrawing: the same key, the same tilt, the same tile. A second
silhouette would mean two marks for the same key.

What varies is what the products differ in:

- **Accent.** BlinkyLite is `#1DB954`; Blinky CMS is the console's `#18C9DF`,
  bright `#5AE3F3` on dark.
- **Nodes.** Four of them, one at each end of the arc. They are what the
  hexagon-and-eye icon they replace was about — a managed set of cards, not
  one card. BlinkyLite manages nothing and its arc is bare.
- **Wordmark.** „Blinky” in the text colour, the product in the accent:
  „Lite” there, „CMS” here. It is a proper noun and is not translated.

## Rules

- **The colours are not here.** The mark's accent is the console's, and the
  console's colours are roles in `tools/PaletteTool/Palette.cs` (0099). If the
  accent ever moves, it moves there first and the two SVGs follow.

- **There is one mark for the whole product.** The console, the API, the
  workstation service and its tray UI all resolve to these two SVGs. Until
  0098 the service and the API had different artwork, which is how a person
  ends up unsure whether the thing in the tray is ours.
- **The key carries no Yubico logo.** It is somebody else's trademark and this
  repository is public. The touch sensor is a ring with a point.
- **The gold contacts stay gold.** They are the one part of the mark that is
  not a brand colour, and they are why it reads as a key rather than a fob.
- **`scripts/build-icons.ps1` is gone** (0098). It built the `.ico` files by
  downscaling the 256 px artwork, so the 16 px tray icon was a smudge of a
  detailed drawing; `build-assets.mjs` renders the simplified mark at that
  size instead.
