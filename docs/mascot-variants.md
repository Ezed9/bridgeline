# bridgeline mascot — ASCII variants

A spider at a doorway. The crawler *is* the creature, and it sits at a threshold it will not cross.

**Character set:** printable ASCII plus `─ │ ┌ ┐ └ ┘ ├ ┤ ┬ ┴ ┼ ╱ ╲`. No emoji, no exotic Unicode.
**Budget:** max 5 lines tall, max 11 columns wide.
**Aspect ratio:** terminal cells are ~1:2 (w:h). A leg drawn one column per row reads at ~63°, not 45° — it looks *steeper* than you drew it. Every leg below that needs to look splayed advances **two columns per row**, and horizontal `-` runs are used for the middle legs, which is the only way to buy real width in a 5-row box.

Dimensions are given as `lines × max columns`, trailing spaces not counted.

---

## 1. rest

Sits in the banner at startup. Calm, watchful, a little characterful.

### R1 — wide stance

```
 \\  //
--(oo)--
 //  \\
```

Baseline silhouette: four legs up, four down, two horizontal middles. Reads as a spider at a glance because the mass is central and the strokes radiate. **3 × 8.**

### R2 — long-legged

```
 \      /
  \\  //
 --(oo)--
  //  \\
 /      \
```

Two-segment legs with a knee above the body line, the way a real spider actually stands. The most convincing of the set, and the most expensive in vertical space. **5 × 9.**

### R3 — tiny

```
\\ //
(o:o)
// \\
```

Absolute floor of the size budget. Honestly: this is the weakest one — at 5 columns the chevrons stop reading as legs and it looks like a beetle, or an owl. Included only to mark where the shape breaks down. **3 × 5.**

### R4 — winking

```
 \\  //
--(o-)--
 //  \\
```

R1 with one eye closed. Buys the "little characterful" the brief asks for at zero cost, and gives `watching` an obvious delta to open the eye into. **3 × 8.**

### R5 — on a thread

```
   │
 \\  //
--(oo)--
 //  \\
```

The single strongest *spider* cue in the whole document: nothing else hangs from a line. Costs one row, and the thread is one column off true centre (body spans cols 3–6, thread at col 4) — imperceptible in practice. **4 × 8.**

**Section assessment.** R1, R4 and R5 are the same drawing and should be treated as one family. R2 is the best-looking but its 5-row height makes it a splash-screen mascot, not a header one. R3 does not read as a spider and I would not ship it.

---

## 2. watching

Shown during a crawl. Alert. Must read as the *same creature* as `rest`, one mood over.

### W1 — wide eyes

```
 \\  //
--(OO)--
 //  \\
```

Pure eye delta from R1: `oo` → `OO`. Nothing else moves, so the identity is guaranteed. Subtle, but that is the point — this is a running-state indicator, not an alarm. **3 × 8.**

### W2 — foreleg raised

```
 \\  ///
--(oo)--
 //  \\
```

One extra `/` on the right: a front leg lifted, testing the air. Delta is asymmetric, which reads as *attention pointed somewhere* rather than generic alertness. Slight risk of looking like a typo. **3 × 8.**

### W3 — rearing

```
 \    /
  \\//
--(OO)--
 //  \\
```

Forelegs pulled in and up over the body. The most legibly "alert" of the five, but it changes height (3 → 4 rows) and the tucked forelegs momentarily read as a peaked roof. **4 × 8.**

### W4 — alert on the thread

```
   │
 \\  //
--(OO)--
 //  \\
```

Partner to R5: same thread, eyes opened. If you ship R5 at rest, this is its only correct pairing. **4 × 8.**

### W5 — long-legged, alert

```
 \      /
  \\  //
 --(OO)--
  //  \\
 /      \
```

Partner to R2, eye delta only. **5 × 9.**

**Section assessment.** W1, W4 and W5 are honest small deltas. W2 is clever but fragile — at a glance the third slash reads as a rendering artefact, not a leg. W3 is the only one that changes the silhouette, which makes it more visible but weakens the "same creature, different mood" requirement; it is arguably already halfway to `braced`, which is a problem, because those two states must not compete.

---

## 3. braced

Beside a refusal. The hero moment. The reader must feel *it stopped something*.

### B1 — in the doorway

```
┌────────┐
│ \\  // │
│--(OO)--│
│ //  \\ │
```

The spider from R1 wedged in a door frame, its middle legs pressed flat against both jambs. The frame is open at the bottom — it is a doorway you walk *through*, not a box. The horizontal lintel is a hard high-contrast rule that no other state has, which is what makes this readable from the corner of the eye. **4 × 10.**

### B2 — planted on the threshold

```
 \\  //
--(OO)--
_/    \_
────────
```

Hind legs driven out to the corners with `_` feet flat on a ground line. Trades leg *count* below the body (four down to two) for leg *spread*, and the flat feet sell weight and bracing. Works without any frame, so it survives narrow terminals. **4 × 8.**

### B3 — holding the jamb

```
 \\  //│
--(OO)-│
 //  \\│
```

One jamb only, on the right: the spider bracing against the thing it is refusing, with a clear directional read ("the block is over there"). Cheapest braced variant — same height as rest. **3 × 8.**

### B4 — maximum spread

```
\\    //
--(OO)--
//    \\
```

Legs pushed flush to the outer columns. Honestly: this fails the brief. It is a one-column delta from R1 and in peripheral vision it is indistinguishable from rest — you have to *read* it to notice. Included as the negative example. **3 × 8.**

### B5 — closed gate

```
┌────────┐
│ \\  // │
│--(OO)--│
│ //  \\ │
┴────────┴
```

B1 with a threshold line and `┴` feet where the jambs meet the floor. More massive, and the closed bottom edge does say "sealed". But closing the shape turns a doorway into a *frame*, and a framed spider reads as a portrait of a spider rather than a spider in your way. B1's open bottom is the better idea. **5 × 10.**

**Section assessment.** B1 is the only variant that produces a genuine double-take. B2 is the best frameless option and the right fallback. B3 is efficient but its asymmetry can read as a rendering glitch on the first encounter. B4 does not work. B5 is worse than B1 despite doing more.

**A note on `╱ ╲`:** the true-45° box-drawing diagonals (U+2571/U+2572) give a visibly wider, cleaner splay than `/ \` and are tempting for `braced`:

```
╲╲    ╱╱
--(OO)--
╱╱    ╲╲
```

I would not ship it. Font coverage for these two codepoints is far patchier than for `─ │ ┌ ┐`, and when they miss, the terminal substitutes from a fallback face at a different advance width — which shears the drawing sideways. That is exactly the plain-xterm-over-SSH case the constraints exist to protect. Stick to ASCII `/ \` for legs; reserve box-drawing for the frame, where a fallback glyph degrades gracefully instead of misaligning.

---

## Recommendation

**R1 (wide stance) / W1 (wide eyes) / B1 (in the doorway).**

All three are literally the same eight-stroke drawing — `\\ //` over `--(..)--` over `// \\` — so identity across states is not a matter of resemblance, it is a matter of the glyphs being byte-identical outside the two eye characters. `rest` → `watching` changes exactly two characters (`oo` → `OO`), which is the smallest delta that is still visible in a 12px terminal font, and it correctly reads as a mood shift rather than a different creature. `braced` keeps the spider untouched and adds a frame around it, so the reader recognises the animal instantly and only then registers that it is now wedged in a doorway with its middle legs jammed against both jambs — which is the right order of perception for a refusal message.

On peripheral legibility: `braced` wins because the delta is a *horizontal rule*, not a limb. The eye picks up the lintel of `┌────────┐` as a bar of contrast well before it resolves any leg, and no other state has a horizontal element at all. Compare B4, which changes only leg position and is invisible until you focus on it. The one real cost is that B1 is 4 rows against R1's 3 — pad `rest` and `watching` with a leading blank line so all three states occupy a stable 4-row block, and the header will not jump when a refusal fires.

If the header must be exactly 3 rows, substitute **B3** for B1 and accept a weaker hero moment. Do not substitute B4.

---

## Logo lockups

### Option A — two-line, spider-forward

```
\\(oo)//  bridgeline
//    \\
```

The body and the wordmark share a baseline, so the eyes sit at cap height next to the `c` and the whole thing reads as one object. Losing the middle legs to the one-line-body constraint costs some spider-ness, but the hind legs on line 2 recover it — the creature is unmistakably standing on something. Line 1 is 19 columns, line 2 is 8. **2 × 19.**

### Option B — one-line, gate-forward

```
│--(oo)--│ bridgeline
```

For places that genuinely cannot take two lines: a README badge row, an npm description, the first line of `--help`. Being honest about what this is — on one line the top and bottom legs are gone, so it is a pair of eyes braced between two jambs, not a legible spider. It works because the jambs carry the *gate* half of the name and the reader's eye supplies the *crawl* half from the word itself. Use A wherever two lines fit. **1 × 20.**
