# Presentation deck

`HappyLab_PS028_TC278.pptx` and the same deck as `HappyLab_PS028_TC278.pdf`. Present from the
PDF on an unfamiliar laptop: PowerPoint substitutes fonts between machines, and a PDF cannot be
changed that way. The speaker notes, with a time budget for each slide, are in the .pptx only.

The deck follows the AIORI-3 order, with one section each: problem (slides 1–2), approach (3),
architecture (4), implementation (5–6, including the live demo) and impact (7–14). It ends with the
references (15) and a thank-you slide (16). It runs to about 13 min 35 s: 9 min 55 s of slides plus a
3 min 40 s demo slot on slide 6, then questions.

## Design

The style follows our project proposal, `A3-PS028-HappyLab-Project-Proposal.pdf` at the repository root.
- **Page and colours.** A white 13.33 × 7.5 in page with ink text (`#1B1F2A`) and grey secondary text
  (`#5A6275`). Slide titles are bold, top left, in the proposal's blue (`#1226C8`). Panels are light blue
  (`#EEF1FF`) with bold blue panel titles, and lists use blue filled circles.
- **Type sizes.** Titles 32 pt, panel titles 18 pt bold, body 20 pt, secondary text 16 pt, figure captions
  13 pt, header and footer 11 pt.
- **Header and footer.** A small centred header reads "AIORI 3" and the section name. A small grey footer
  carries the team code, the date and "n / 16".
- **Title, references and closing slides.** These are laid out like the proposal's title, bibliography and
  closing pages. The title and closing slides carry the AIORI logo and the race illustration.
- **Logo.** `assets/aiori_logo.png` is the organisers' own image, taken out unchanged (see
  `assets/README.md`).
- **Typeface.** Calibri, as in the proposal.

## Figures

The deck uses slide versions of three report figures, in `docs/figures/slides/`, written by
`src/analysis/slide_figures.py`.
- **Separate from the report.** The report figures in `docs/figures/` are not used here and are not changed.
- **Same data.** The slide figures read the same `docs/figures/figures_data.json` that
  `figures.py --check` verifies against the datasets.
- **Drawn for the slide.** Each figure is drawn at the size it is placed on the slide, so the type in a
  chart is the size the audience sees: 14 pt ticks and 15 pt axis titles.
- **Simplified.**
  - Slide 8 is one panel: setup against the oracle for both clients.
  - Slide 9 keeps both rows: the sweep points, the flip bracket, T, and the jitter cells as small unlabelled
    diamonds. It has no model curves and no σ labels.
  - Slide 10 shows all eight residuals as dots inside two labelled bands, as measured.
  - Lines are labelled directly, with no legend boxes.

```
.venv/bin/python src/analysis/slide_figures.py     # rewrites docs/figures/slides/
```

## Rebuild

```
cd deck
npm ci                                  # pptxgenjs, pinned in package-lock.json
node build_deck.js                      # writes HappyLab_PS028_TC278.pptx
soffice --headless --convert-to pdf HappyLab_PS028_TC278.pptx
```

`soffice` is LibreOffice (`sudo apt install libreoffice-impress`).
- **Typeface.** The .pptx names Calibri, which ships with Office. LibreOffice renders it with Carlito,
  Calibri's metric twin (`sudo apt install fonts-crosextra-carlito`). Carlito has the same character widths,
  so the line breaks match, and the PDF embeds it.
- **Check before presenting.** Run `pdffonts HappyLab_PS028_TC278.pdf`. All text should be Carlito. The
  only other fonts are OpenSymbol (list bullets) and DejaVu Sans Bold (the ✓ ticks on slide 3, a glyph
  Carlito lacks). Noto Sans or any other text font means Carlito was missing when the PDF was exported.

## Where the content comes from

- **Numbers:** every measured number on a slide is read from `deck_numbers.json`. Each entry names
  the doc it comes from (`docs/report.md` or a findings doc) and the exact text it quotes.
- **Figures:** the slide versions in `docs/figures/slides/` (see Figures above), embedded as exported.
- **Checks:** `src/tests/test_deck.py`, run by `scripts/test.sh`, fails in any of these cases:
  - a figure the deck names is missing from `docs/figures/slides/`;
  - a slide figure is placed at a size other than the one it was drawn for;
  - a number's text no longer appears in its source doc;
  - the committed .pptx lacks a number or an unchanged figure;
  - T appears rounded to one decimal;
  - a slide lacks speaker notes with a time budget;
  - the slide clock has a gap or overlap;
  - slide 3's test count differs from its notes;
  - the prior-work citation number differs from the References slide;
  - the title-slide logo differs from the organisers' file;
  - the PDF is missing.
- **Totals:** the 1,328-run total is recomputed from the dataset docs. The 709 tests figure is
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
