# Presentation deck

`HappyLab_PS028_TC278.pptx` and the same deck as `HappyLab_PS028_TC278.pdf`. Present from the
PDF on an unfamiliar laptop: PowerPoint substitutes fonts between machines, and a PDF cannot be
changed that way. The speaker notes, with a time budget for each slide, are in the .pptx only.

The deck follows the AIORI-3 order, with one section each: problem (slides 1–2), approach (3),
architecture (4), implementation (5–6, including the live demo) and impact (7–14). It runs to about
13 min 20 s: 9 min 40 s of slides plus a 3 min 40 s demo slot on slide 6.

## Rebuild

```
cd deck
npm ci                                  # pptxgenjs, pinned in package-lock.json
node build_deck.js                      # writes HappyLab_PS028_TC278.pptx
soffice --headless --convert-to pdf HappyLab_PS028_TC278.pptx
```

`soffice` is LibreOffice (`sudo apt install libreoffice-impress`). Text uses Arial, which
LibreOffice renders with the metric-identical Liberation Sans, so the PDF keeps the .pptx line breaks.

## Where the content comes from

- **Numbers:** every measured number on a slide is read from `deck_numbers.json`. Each entry names
  the doc it comes from (`docs/report.md` or a findings doc) and the exact text it quotes.
- **Figures:** they are the PNGs in `docs/figures/`, embedded as exported. Nothing is re-plotted.
- **Checks:** `src/tests/test_deck.py`, run by `scripts/test.sh`, fails in any of these cases:
  - a figure the deck names is missing from `docs/figures/`;
  - a number's text no longer appears in its source doc;
  - the committed .pptx lacks a number or an unchanged figure;
  - T appears rounded to one decimal;
  - a slide lacks speaker notes with a time budget;
  - the PDF is missing.
- **Totals:** the 1,328-run total is recomputed from the dataset docs. The 704 tests figure is
  the `scripts/test.sh` count on 2026-11-25, and the slide gives that date.

## Live demo (slide 6)

1. **At the venue:** run `make demo-check`. It is a read-only pre-flight covering kernel modules, namespaces,
   sudo, curl 8.5.0, the Chromium build and disk space.
2. **Before the talk:** build the lab with `sudo src/lab/setup.sh`.
3. **On stage:** run `make demo`. It verifies the lab, runs curl once in S1, re-reads the capture against the
   record, opens the connection race timeline and prints the numbers in large type, all in under a minute of
   machine time. The lab stays up, so `make demo SCENARIO=S4 CLIENT=chromium` can follow if a judge asks.
4. **If anything fails live,** `make demo` prints FAIL and puts the lab back to a verified baseline. Use the
   committed runs in `examples/` instead.
5. **Afterwards:** run `sudo src/lab/teardown.sh`.

A live run is a demonstration only and joins no dataset. It is written to `data/demo/` (gitignored) under a
`demo-` session ID that no manifest can list. `make demo-isolation-check` checks that two demo runs leave
every summary byte-identical.
