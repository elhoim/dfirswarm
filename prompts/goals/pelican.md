## Goal

Draw a pelican riding a bicycle as `work/pelican.svg`: one self-contained SVG,
hand-authored, no external assets and no libraries. Opening the file in a
browser shows the drawing.

What "good" means here — judge against all of it:

- It reads as a **pelican**, not a generic bird: the long bill with the throat
  pouch under it is the defining feature. Webbed feet, plump body.
- It reads as **riding**: wings on the handlebars, body over the saddle, feet
  at the pedals, and a frame that could actually hold a bird. Not a bird
  floating near a bicycle.
- The **bicycle is a bicycle**: two spoked wheels, a frame with triangles, a
  chain, handlebars, a saddle.
- Craft: deliberate palette, grouped `<g>` anatomy (wheel, frame, bird, pouch)
  so the thing is editable, layered in a sensible z-order.

## Definition of done

`work/pelican.svg` is a single self-contained SVG that parses as XML, contains
no external references, and draws a pelican on a bicycle. At least two
different agents have posted an `approved` line on `threads/main` naming the
content hash they reviewed, and the file has not changed since.

## Checks

- `test -s work/pelican.svg`
- `python3 -c "import xml.dom.minidom; xml.dom.minidom.parse('work/pelican.svg')"`
- `grep -qi '<svg' work/pelican.svg`
- `! grep -Eqi '<(script|image|use[^>]*href="http)' work/pelican.svg`
- `test "$(grep -l '^approved ' threads/main/*.md 2>/dev/null | wc -l | tr -d ' ')" -ge 2`

## How to divide the work

Slices that divide cleanly — check `claims` and take an unclaimed one:

1. Bicycle geometry: wheels, frame, chain, handlebars, saddle.
2. Pelican anatomy: body, neck, head, bill and pouch.
3. Wings, feet and the contact points with the bars and pedals.
4. Palette, background and composition.
5. Verification: render it, look at it, and say what is wrong with numbers —
   wheel circularity, whether the pouch exists below the head, whether the feet
   meet the pedals.

Land your slice into `work/pelican.svg` by claiming it, reading what is there,
adding your part, and releasing. Do not overwrite someone else's group: use
`file_diff` first if you are unsure what changed.

When you believe it is done, post a line beginning with `approved ` on
`threads/main` that names the content hash you checked (take it from
`file_history`). Two different agents must do this, on the same hash, before
anyone calls `done`. If you disagree with the current state, say so with a
`veto` post and what to fix instead.
