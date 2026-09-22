# The mark

Two brackets holding five peers. The brackets are the harness: the sandbox,
the leases, the caps, the sentinel, the part that is not negotiable. Inside
them the swarm is five agents of five different specialisms, drawn the same
size because none of them outranks another and nothing was handed out.

The five colours are the console's own accent tokens, so the mark and the
product it belongs to use one palette rather than two.

| File | Ground | What it is |
| --- | --- | --- |
| `mark.svg` | dark | The five hues raised to the value a dark ground needs |
| `mark-light.svg` | light | The console's `brick`, `slate`, `saffron`, `kelp` and `moss`, verbatim |
| `mark-mono.svg` | any | Everything `currentColor`: it takes the colour of the text around it |
| `favicon.svg` | its own | The tab icon, on the console's `band` ground so it reads on either browser chrome |

Each of the four also has a `.jpg` twin (1024×1024, mark centred on its
ground colour) for places that will not take SVG, such as a slide deck or a
form upload. The SVG is the source; regenerate the JPEGs from it rather than
editing a JPEG directly.

## Using it

**Give it room.** Clear space on every side is the width of one bracket
stroke at that size. The mark is drawn on a 64-unit grid with 8 units of air
already inside it, so a container that crops tighter than the viewBox is
cropping the mark.

**Do not recolour the dots one at a time.** Five specialisms of equal weight
is the whole idea; one dot in a different family reads as the odd one out,
which is the opposite of what this says. Recolour all five or none.

**Below 24 px, use `mark-mono.svg`.** The five hues stop being
distinguishable around there and the colour only muddies the silhouette. The
brackets carry the mark at small sizes, which is why they are the heaviest
element.

**In print, in a seal, on a fax, or anywhere colour may be lost**,
`mark-mono.svg` is the version that survives. Every arrangement here is
designed to still read with the colour taken out.

## The name

The mark is covered by the project's [licence](../LICENSE). The name is not:
see [TRADEMARK.md](../TRADEMARK.md). Fork freely, and give the fork its own
name and its own mark.

`social-preview.png` (1280×640) is the card for GitHub's repository social preview (Settings → Social preview) and for anywhere else a link to the repository unfurls; the site renders its own per-page cards at dfirswarm.ai/assets/og/.

## Social headers

`header-x.jpg` (3000×1000, a 3:1 crop delivered at 2× the platform's own
1500×500) and `header-linkedin.jpg` (3168×792, 2× LinkedIn's personal-profile
1584×396) are the wide banner for X/Twitter's profile header and LinkedIn's
cover photo. LinkedIn's separate company-page banner is a different ratio
(1128×191) and isn't generated here; ask for it if a company page needs one.

**The X margins are set from a measured crop, not the published spec.** A
live screenshot of the first `header-x.jpg` on the X iOS app showed the
wordmark's leading "D" sheared off, at margins (104px, 6.9%) that should
have been inside every "safe zone" figure the usual guides quote. Two
features common to both the source file and the screenshot (the exhibit
tag's ribbon, the tag label's left edge) were used to solve for the actual
transform X applies: it scales the banner to fill the visible height and
centre-crops the width, losing **~8.3% off each side (16.7% of the width,
worse than the ~10% the write-ups describe)**, with no vertical loss on
that device. `header-x.jpg` keeps the lockup inside 170px (11.3%) margins
on that basis; `header-linkedin.jpg` keeps LinkedIn's own documented
1260×300 safe zone but with margins past its minimum (200px sides / 60px
top-bottom, vs. the spec's 162px / 48px) on the same suspicion. Re-check
against a real screenshot before trusting either margin further, and widen
rather than narrow if a future device disagrees.

The design is "the evidence board": the wordmark set in the Instrument Serif
italic the rest of the mark never uses, a case-file exhibit tag pinned over
it at a slight angle, and the five accent colours scattered right as loose
pins rather than the mark's own five dots. It reads as a piece of the case
file itself, not a logo lockup with a tagline bolted on.
