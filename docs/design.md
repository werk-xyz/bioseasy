# Design tokens

The web UI uses these tokens and nothing else, so framework defaults cannot fill the gaps. The
aim is the calm of an Apple product without copying one: a quiet ground, cards as the one layout
primitive, hierarchy from weight and tracking rather than from size jumps.

## Palette

A cool, faintly green off-white. The green is the product's own note - it is the colour of a finished backup - so the ground carries a trace of it
instead of the neutral grey a system palette would use.

| Token | Light | Dark | Use |
|---|---|---|---|
| `--paper` | `#f2f5f4` | `#0c1011` | page ground, behind everything |
| `--surface` | `#ffffff` | `#151b1c` | cards, panels, table rows, menus |
| `--surface-sunken` | `#e9efec` | `#1d2426` | hover, input wells, the track of a bar |
| `--ink` | `#0f1a17` | `#e8edeb` | body text |
| `--muted` | `#5c6d67` | `#99a8a3` | secondary text (contrast checked against both grounds) |
| `--line` | `#dfe6e2` | `#252f31` | hairlines: separators, card edges, input borders |
| `--accent` | `#0e7a52` | `#46c68d` | primary action, current backup generation |
| `--warn` | `#95580a` | `#e0a24a` | stale backup, attention needed |
| `--bad` | `#b0302a` | `#f08a80` | failed backup, unreachable storage |

State is never carried by colour alone: every status also has a word ("OK", "Overdue", "Failed")
and a shape marker.

## Elevation

Three levels, no more. A card sits on the ground with a hairline and no shadow; only things that
float above the page (the activity popover, a toast, an open menu) get a shadow, and a soft one.
No gradients, no glassmorphism, no coloured glows.

| Token | Value | Use |
|---|---|---|
| `--shadow-pop` | `0 8px 24px rgba(8, 20, 16, .12)` | popover, menu, toast |
| `--radius-sm` | `7px` | inputs, small controls, generation blocks |
| `--radius` | `11px` | buttons, cards, flashes |
| `--radius-lg` | `16px` | the large panels on the device page |

## Type

**System fonts only.** The container serves no web fonts and makes no requests to font CDNs, so
on an Apple device the UI is set in SF, on Windows in Segoe, on Linux in whatever the system
provides - which is also why the interface feels native rather than branded on each of them.

- UI and body: `system-ui, -apple-system, "Segoe UI", Roboto, sans-serif`
- Numbers, UDIDs, paths: `ui-monospace, "SF Mono", Menlo, Consolas, monospace`
- **The wordmark only:** `"Iowan Old Style", "Palatino Linotype", Palatino, Georgia, serif`

The serif used to set every heading in the app. It now sets exactly one thing - the word
"bioseasy" in the header - where it reads as a mark rather than as a book. Headings are the system
sans, sized and tracked instead of styled:

| Level | Size | Weight | Tracking |
|---|---|---|---|
| Page title (`h1`) | 1.75rem | 600 | `-0.021em` |
| Section (`h2`) | 1.1875rem | 600 | `-0.011em` |
| Sub-section (`h3`) | 1rem | 600 | normal |
| Body | 1rem / 1.5 | 400 | normal |
| Secondary (`.meta`) | 0.875rem | 400 | normal |
| Label above a group | 0.75rem uppercase | 600 | `0.04em` |

Negative tracking on the two large sizes is the single most Apple-like move here and costs
nothing: large text set at default tracking looks loose next to it.

## Layout primitive

**The generation strip**: a horizontal row of backup generations per device, newest left, fading
with age, exactly like the logo. Used on the overview, the device page and the backup list. The
segments share the available width rather than scrolling out of it - a row of seven that needs a
scrollbar is not a summary any more.

No icon-card grids, no stat banners, no numbered 1-2-3 sequences, no coloured left borders on
cards.

## Cards and rows

Two containers, and they cover almost everything:

- **Card** (`.card`): surface, hairline, `--radius-lg`, used for one coherent thing.
- **Row list** (`.rows`): a card whose children are separated by hairlines, each row a single
  subject - a device, a token, a user. Rows do not repeat the card's border; the separator is the
  only line, and the last row has none. This is the shape Apple's own Settings uses, and it is the
  reason this UI needs so few boxes.

## Buttons

- Primary: filled `--accent`, `--radius`, never full width unless it is the only control in a
  narrow column on a phone. A button that stretches across a desktop form reads as a generated
  form, not a decision.
- Secondary: `--surface` with a hairline.
- Quiet: text only, used inside rows.
- Every button keeps a 44px touch target; the visual height comes from padding, not from a
  stretched box.

## Theme

Follows `prefers-color-scheme` by default; a toggle in the footer stores an explicit choice.

## Blockquote

For the "Status:" callouts in the docs pages and one literal quoted source: a left rule in
`--line` plus `--muted` text - never the browser's unstyled default indent.

## Toast

A small, dismissible notice, top-right, below the header - never covering the nav, never the
popover itself. Used for "something in the background changed", not for form feedback, which stays
inline. `--surface`, hairline, `--shadow-pop`; disappears after a few seconds or on dismiss.
