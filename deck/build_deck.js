// HappyLab presentation deck (AIORI-3 PS-028, team NetDefenders, A3-PS028-TC278).
//
//   cd deck && npm ci && node build_deck.js       # writes HappyLab_PS028_TC278.pptx
//
// Every measured number comes from deck_numbers.json (each one is checked verbatim against its
// source doc by src/tests/test_deck.py). The charts are the slide versions in docs/figures/slides/
// (src/analysis/slide_figures.py): simpler drawings of the same figures_data.json as the report figures,
// which stay unchanged in docs/figures/. The test also fails if a figure named in FIGURES is missing.

const path = require("path");
const pptxgen = require("pptxgenjs");

const REPO = path.resolve(__dirname, "..");
const N = Object.fromEntries(
  Object.entries(require("./deck_numbers.json"))
    .filter(([k]) => !k.startsWith("_"))
    .map(([k, v]) => [k, v.text]));
const n = (k) => { if (!(k in N)) throw new Error(`deck_numbers.json has no ${k}`); return N[k]; };

// Figures used by the deck. src/tests/test_deck.py reads this list.
const FIGURES = {
  oracle: "docs/figures/slides/slide8_setup_vs_oracle.png",
  budget: "docs/figures/slides/slide9_latency_budget.png",
  he: "docs/figures/slides/slide10_he_linearity.png",
};
// Placed size in inches; slide_figures.py renders each figure at exactly this size (its SIZES), so
// the type in a chart is the size the audience sees.
const FIG_SIZE = { oracle: [6.4, 5.3], budget: [9.4, 5.3], he: [9.4, 5.3] };
const fig = (k) => path.join(REPO, FIGURES[k]);

// ---- theme ---------------------------------------------------------------------------------
// The style of the project proposal (A3-PS028-HappyLab-Project-Proposal.pdf, repository root): white
// pages, a bold blue title at top left, light blue panels with bold blue panel titles, blue numbered
// circles, a small centred "AIORI 3  <section>" header and a small footer with "n / total".
// Colours are the proposal's own.
const BLUE = "1226C8";     // titles, panel titles, header, numbered circles, table headers
const INK = "1B1F2A";      // body text
const MUTED = "5A6275";    // secondary text and footer (6:1 on white)
const PANEL = "EEF1FF";    // panel fill
const ORANGE = "E8710A";   // the one highlighted stat, as in the proposal (large bold text only)
const GREEN = "138808";    // the race illustration: the connection that wins
const RED = "B3261E";      // the race illustration: the attempt that gets no answer
const LINE = "5A6275";     // borders and diagram lines
const CURL = "1F66B8";     // matches the figures' curl blue (always with a circle)
const CHR = "B4461C";      // darker than the figures' orange so text passes contrast (always with a triangle)
// Calibri, as in the proposal; ships with Office. The PDF is exported with Carlito, Calibri's metric
// twin, embedded (same widths, so the same line breaks). Present from the PDF.
const FONT = "Calibri";
// Type sizes in points: title, subtitle and panel titles, body, secondary, captions, header and footer.
const PT = { title: 32, sub: 18, body: 20, second: 16, caption: 13, chrome: 11 };
const TOTAL = 16;          // slides; the footer reads "n / 16" as the proposal's does
const DATE = "26 November 2026";
const Y0 = 1.5;            // top of the content area, below the title

const pres = new pptxgen();
pres.layout = "LAYOUT_WIDE"; // 13.333 x 7.5 in, the proposal's page size
pres.title = "HappyLab: Happy Eyeballs IPv4/IPv6 fallback measurement (PS-028)";
pres.author = "Team NetDefenders";
pres.theme = { headFontFace: FONT, bodyFontFace: FONT };
const W = 13.333;

// One layout per section: the header names the section, so it lives on the layout.
// (Layout text objects take plain strings only, not styled runs.)
const chrome = (section) => [
  { text: { text: `AIORI 3     ${section}`,
            options: { x: 0, y: 0.16, w: W, h: 0.26, fontFace: FONT, fontSize: PT.chrome, bold: true, color: BLUE,
                       align: "center", margin: 0 } } },
  { text: { text: `Team NetDefenders  •  A3-PS028-TC278  •  ${DATE}`,
            options: { x: 0.6, y: 7.05, w: 8, h: 0.26, fontFace: FONT, fontSize: PT.chrome, color: MUTED, margin: 0 } } },
];
const LAYOUTS = {};
for (const section of ["Problem", "Approach", "Architecture", "Implementation", "Impact", "References"]) {
  LAYOUTS[section] = `CONTENT ${section}`;
  pres.defineSlideMaster({ title: LAYOUTS[section], background: { color: "FFFFFF" }, objects: chrome(section), placeholders: [] });
}
pres.defineSlideMaster({ title: "TITLE", background: { color: "FFFFFF" }, objects: [] });
// A content slide in the current section, with "n / total" at bottom right.
const content = () => {
  const sl = pres.addSlide({ masterName: LAYOUTS[S], sectionTitle: S });
  sl.addText(`${pres.slides.length} / ${TOTAL}`, { x: 11.15, y: 7.05, w: 1.6, h: 0.26, fontFace: FONT, fontSize: PT.chrome,
                                                    color: MUTED, align: "right", margin: 0, isTextBox: true });
  return sl;
};

// ---- helpers -------------------------------------------------------------------------------
function title(s, t) {
  s.addText(t, { x: 0.6, y: 0.58, w: W - 1.2, h: 0.62, fontFace: FONT, fontSize: PT.title, bold: true,
                 color: BLUE, valign: "middle", margin: 0, isTextBox: true });
}
function text(s, t, o) {
  s.addText(t, Object.assign({ fontFace: FONT, fontSize: PT.body, color: INK, valign: "top", margin: 0,
                               isTextBox: true }, o));
}
// Bold blue title inside a panel, as in the proposal.
function panelTitle(s, t, x, y, w) {
  text(s, t, { x, y, w, h: 0.4, fontSize: PT.sub, bold: true, color: BLUE });
}
// Evidence tag chip: the label is always written out, so no tag relies on colour.
function tag(s, label, x, y, w) {
  s.addText(label, { shape: pres.ShapeType.roundRect, rectRadius: 0.06, x, y, w: w || 3.6, h: 0.42,
                     fill: { color: "FFFFFF" }, line: { color: INK, width: 1 }, fontFace: FONT,
                     fontSize: PT.second, bold: true, color: INK, align: "center", valign: "middle", margin: 0 });
}
function card(s, x, y, w, h) {
  s.addShape(pres.ShapeType.roundRect, { x, y, w, h, rectRadius: 0.08, fill: { color: PANEL },
                                         line: { color: PANEL } });
}
// Blue filled circle with a white label: the proposal's numbered list marker.
function dot(s, label, x, y, d, font) {
  s.addText(label, { shape: pres.ShapeType.ellipse, x, y, w: d, h: d, fill: { color: BLUE }, line: { color: BLUE },
                     fontFace: font || FONT, fontSize: PT.second, bold: true, color: "FFFFFF",
                     align: "center", valign: "middle", margin: 0 });
}
// Client markers repeat the figures' encoding: curl = circle, Chromium = triangle.
function curlMark(s, x, y, d = 0.26) {
  s.addShape(pres.ShapeType.ellipse, { x, y, w: d, h: d, fill: { color: CURL }, line: { color: CURL, width: 1 } });
}
function chrMark(s, x, y, d = 0.28) {
  s.addShape(pres.ShapeType.triangle, { x, y, w: d, h: d * 0.9, fill: { color: CHR }, line: { color: CHR, width: 1 } });
}
function table(s, rows, o) {
  s.addTable(rows, Object.assign({ x: 0.6, y: Y0, w: 12.15, rowH: 0.52, fontFace: FONT, fontSize: PT.body, color: INK,
                                   border: { type: "solid", pt: 0.75, color: "C9CEDD" }, valign: "middle",
                                   margin: [0, 0.12, 0, 0.12] }, o));
}
// The proposal's race illustration panel (title and closing slides): IPv6 gets no answer, IPv4 connects
// after the attempt delay. Labels are the deck's own.
function race(s) {
  const px = 8.1, py = 1.75, pw = 4.65, ph = 3.6;
  card(s, px, py, pw, ph);
  const y6 = py + 1.15, y4 = py + 2.45, x6 = px + 1.15, x4 = px + 1.95, xe = px + pw - 0.45;
  text(s, "IPv6", { x: px + 0.3, y: y6 - 0.2, w: 0.8, h: 0.4, fontSize: PT.sub, bold: true });
  text(s, "IPv4", { x: px + 0.3, y: y4 - 0.2, w: 0.8, h: 0.4, fontSize: PT.sub, bold: true });
  s.addShape(pres.ShapeType.line, { x: x6, y: y6, w: xe - x6, h: 0, line: { color: RED, width: 2, dashType: "dash" } });
  s.addShape(pres.ShapeType.mathMultiply, { x: xe - 0.14, y: y6 - 0.16, w: 0.32, h: 0.32, fill: { color: RED }, line: { color: RED } });
  text(s, "SYN … no answer", { x: x6 + 0.6, y: y6 - 0.52, w: 2.4, h: 0.32, fontSize: PT.second, italic: true, color: RED, align: "right" });
  s.addShape(pres.ShapeType.line, { x: x4, y: y4, w: xe - x4, h: 0, line: { color: GREEN, width: 2.5 } });
  s.addShape(pres.ShapeType.ellipse, { x: xe - 0.14, y: y4 - 0.14, w: 0.28, h: 0.28, fill: { color: GREEN }, line: { color: GREEN } });
  text(s, "connected", { x: xe - 1.6, y: y4 + 0.2, w: 1.75, h: 0.32, fontSize: PT.second, bold: true, color: GREEN, align: "right" });
  for (const [x, y] of [[x6, y6], [x4, y4]]) {
    s.addShape(pres.ShapeType.line, { x, y, w: 0, h: y4 + 0.6 - y, line: { color: LINE, width: 0.75, dashType: "sysDot" } });
    s.addShape(pres.ShapeType.ellipse, { x: x - 0.11, y: y - 0.11, w: 0.22, h: 0.22, fill: { color: BLUE }, line: { color: BLUE } });
  }
  s.addShape(pres.ShapeType.line, { x: x6, y: y4 + 0.5, w: x4 - x6, h: 0,
                                    line: { color: LINE, width: 1, beginArrowType: "triangle", endArrowType: "triangle" } });
}
function notes(s, budget, clock, beats, remember) {
  const lines = [`TIME: ${budget} (clock ${clock})`, ""];
  for (const [t, say] of beats) lines.push(`[${t}] ${say}`, "");
  lines.push(`NUMBER NOT TO FORGET: ${remember}`);
  s.addNotes(lines.join("\n"));
}
function sec(name) { pres.addSection({ title: name }); return name; }
function img(s, key, x, y, alt) {
  const [w, h] = FIG_SIZE[key];
  s.addImage({ path: fig(key), x, y, w, h, altText: alt });
}

// =============================================================================================
// 1. Title (Problem)
let S = sec("Problem");
let s = pres.addSlide({ masterName: "TITLE", sectionTitle: S });
// The proposal's title page: logo top left, the big blue name, the subtitle, the people, the event line;
// the race illustration on the right.
s.addImage({ path: path.join(__dirname, "assets", "aiori_logo.png"), x: 0.6, y: 0.45, w: 1.2, h: 1.2 * 119 / 120,
             altText: "AIORI logo" });
text(s, "HappyLab", { x: 0.6, y: 1.9, w: 7.0, h: 0.95, fontSize: 52, bold: true, color: BLUE });
text(s, "Happy Eyeballs IPv4/IPv6 Fallback Measurement", { x: 0.6, y: 2.9, w: 7.0, h: 1.1, fontSize: 30 });
text(s, "A controlled dual-stack lab that measures, from packet captures, how curl and Chromium race IPv6 against IPv4 when one path fails or slows.",
     { x: 0.6, y: 4.1, w: 7.0, h: 0.62, fontSize: PT.second, color: MUTED });
text(s, [
  { text: "Sam Rajeev · Pranav Murali", options: { bold: true, fontSize: PT.body, breakLine: true } },
  { text: "Mentor: Dr. Monika Puttaramaiah", options: { fontSize: PT.second, color: MUTED } },
], { x: 0.6, y: 5.1, w: 7.0, h: 0.75 });
text(s, "AIORI-3 · PS-028 · Team NetDefenders · A3-PS028-TC278", { x: 0.6, y: 6.1, w: 7.0, h: 0.35, fontSize: PT.second });
race(s);
notes(s, "20s", "0:00-0:20", [
  ["20s", "We are NetDefenders, problem statement PS-028. HappyLab is a lab that measures, from the packets, how two real clients - curl and Chromium - race IPv6 against IPv4 when one path is broken or slow."],
], "none yet - just the name: HappyLab, PS-028.");

// 2. The problem
s = content();
title(s, "A broken IPv6 path makes every connection wait");
text(s, [
  { text: "Dual-stack hosts get an AAAA and an A answer, and usually try IPv6 first.", options: { bullet: true, breakLine: true } },
  { text: "If the IPv6 path is broken or slow, that first SYN goes unanswered.", options: { bullet: true, breakLine: true } },
  { text: "Happy Eyeballs (RFC 8305) bounds the wait: after a short delay, also try IPv4, and keep whichever handshake completes first.", options: { bullet: true } },
], { x: 0.6, y: Y0 + 0.1, w: 6.5, h: 3.5, paraSpaceAfter: 14 });
// diagram: what the client does while it waits
card(s, 7.6, Y0, 5.15, 3.7);
panelTitle(s, "While the client waits", 7.9, Y0 + 0.2, 4.6);
const dy = [2.45, 3.4, 4.35];
text(s, "IPv6 SYN", { x: 7.9, y: dy[0], w: 1.6, h: 0.4, bold: true });
s.addShape(pres.ShapeType.line, { x: 9.55, y: dy[0] + 0.2, w: 2.85, h: 0, line: { color: RED, width: 2, dashType: "dash" } });
text(s, "no reply", { x: 10.4, y: dy[0] + 0.3, w: 2.0, h: 0.35, fontSize: PT.second, italic: true, color: RED, align: "right" });
text(s, "wait", { x: 7.9, y: dy[1], w: 1.6, h: 0.4, bold: true });
s.addShape(pres.ShapeType.line, { x: 9.55, y: dy[1] + 0.2, w: 2.85, h: 0, line: { color: LINE, width: 1.5, beginArrowType: "triangle", endArrowType: "triangle" } });
text(s, "how long?", { x: 10.4, y: dy[1] + 0.3, w: 2.0, h: 0.35, fontSize: PT.second, color: MUTED, align: "right" });
text(s, "IPv4 SYN", { x: 7.9, y: dy[2], w: 1.6, h: 0.4, bold: true });
s.addShape(pres.ShapeType.line, { x: 9.55, y: dy[2] + 0.2, w: 2.85, h: 0, line: { color: GREEN, width: 2.5, endArrowType: "triangle" } });
text(s, "wins", { x: 10.4, y: dy[2] + 0.3, w: 2.0, h: 0.35, fontSize: PT.second, bold: true, color: GREEN, align: "right" });
s.addText("What does racing actually cost, measured from the packets?", {
  shape: pres.ShapeType.roundRect, rectRadius: 0.08, x: 0.6, y: 5.6, w: 12.15, h: 0.9, fill: { color: BLUE },
  line: { color: BLUE }, fontFace: FONT, fontSize: 24, bold: true, color: "FFFFFF", align: "center", valign: "middle" });
notes(s, "60s", "0:20-1:20", [
  ["20s", "On a dual-stack host the resolver returns both an IPv6 and an IPv4 address, and IPv6 is normally tried first. If that path is broken or very slow, the SYN just goes unanswered."],
  ["20s", "Happy Eyeballs, RFC 8305, limits the damage: after a short delay the client also opens an IPv4 attempt and keeps whichever handshake finishes first. RFC 8305 is our reference design, not a predictor of exact times."],
  ["20s", "So the question we set out to answer is the one at the bottom: what does that racing actually cost a real client, measured from the packets, not from configuration?"],
], "no number - the question: what does racing actually cost?");

// 3. What PS-028 asked for, and what we built (Approach)
S = sec("Approach");
s = content();
title(s, "What PS-028 asked for, and what we built");
const reqs = [
  ["2 client implementations", "curl 8.5.0 · Chromium 156.0.8078.4"],
  ["6 failure/delay scenarios", "S1–S6, plus a healthy baseline C0"],
  ["Controlled DNS", "own authoritative DNS, delay per record type"],
  ["Pinned specification", "RFC 8305; HEv3 draft pinned at revision -04"],
  ["≥ 20 repetitions", "20 per client per scenario: 280-run core"],
  ["Packet captures", "one pcap per run, SHA-256 in its record"],
];
reqs.forEach(([a, b], i) => {
  const y = Y0 + i * 0.6;
  dot(s, "✓", 0.6, y + 0.04, 0.4, "Segoe UI Symbol");
  text(s, a, { x: 1.2, y, w: 4.1, h: 0.48, bold: true, valign: "middle" });
  text(s, b, { x: 5.4, y, w: 7.35, h: 0.48, valign: "middle" });
});
const stats = [["1,328", "runs, all certified"], ["5", "certified datasets"], ["709", "tests, 25 Nov 2026"]];
stats.forEach(([v, k], i) => {
  const x = 0.6 + i * 4.15;
  card(s, x, 5.35, 3.85, 1.35);
  text(s, v, { x: x + 0.25, y: 5.35, w: 1.85, h: 1.35, fontSize: 40, bold: true, color: i === 0 ? ORANGE : BLUE, valign: "middle" });
  text(s, k, { x: x + 2.1, y: 5.35, w: 1.65, h: 1.35, fontSize: PT.second, valign: "middle" });
});
notes(s, "40s", "1:20-2:00", [
  ["20s", "Each line here is a PS-028 requirement and what meets it. Two existing clients, six scenarios plus a healthy baseline, our own DNS, a pinned spec - RFC 8305, with the v3 draft pinned at revision 04 because it is still a draft as of today - twenty runs per cell, and a capture for every run."],
  ["20s", "Beyond the brief: 1,328 runs in total across five certified datasets - the 280-run core plus four extension campaigns - and 709 automated tests."],
], "1,328 runs (280 of them are the PS-028 core).");

// 4. Architecture
S = sec("Architecture");
s = content();
title(s, "Architecture: two namespaces, three links");
// diagram
const cx = 0.6, cw = 2.35, sx = 5.0, sw = 2.35, top = Y0, bh = 5.2;
card(s, cx, top, cw, bh);
card(s, sx, top, sw, bh);
panelTitle(s, "hl-client", cx + 0.2, top + 0.15, cw - 0.4);
panelTitle(s, "hl-server", sx + 0.2, top + 0.15, sw - 0.4);
text(s, "curl / Chromium\ntcpdump\nlab gai.conf", { x: cx + 0.2, y: top + 0.65, w: cw - 0.4, h: 1.1, fontSize: PT.second });
text(s, "nginx\nDNS, per-type delay", { x: sx + 0.2, y: top + 0.65, w: sw - 0.4, h: 0.8, fontSize: PT.second });
const links = [["v6 veth", 3.55], ["v4 veth", 4.75], ["ctl veth (DNS)", 5.95]];
links.forEach(([lab, y], i) => {
  s.addShape(pres.ShapeType.line, { x: cx + cw, y, w: sx - cx - cw, h: 0, line: { color: INK, width: 2 } });
  text(s, lab, { x: cx + cw + 0.05, y: y - 0.4, w: sx - cx - cw - 0.1, h: 0.34, fontSize: PT.second, align: "center" });
  if (i < 2) {
    s.addText("netem + ifb", { shape: pres.ShapeType.roundRect, rectRadius: 0.05, x: sx + 0.2, y: y - 0.24, w: 1.95, h: 0.48,
                               fill: { color: "FFFFFF" }, line: { color: BLUE, width: 1.25 }, fontFace: FONT,
                               fontSize: PT.second, bold: true, color: BLUE, align: "center", valign: "middle", margin: 0 });
    text(s, "no qdisc", { x: cx + 0.2, y: y - 0.17, w: cw - 0.4, h: 0.34, fontSize: PT.second, color: MUTED });
  } else {
    text(s, "never impaired", { x: sx + 0.2, y: y - 0.17, w: sw - 0.4, h: 0.34, fontSize: PT.second, color: MUTED });
  }
});
// why
const why = [
  ["Server-side netem + ifb", "capture sees every SYN as sent"],
  ["One veth link per family", "impair IPv4 or IPv6 alone"],
  ["Own DNS, delay per type", "S6 delays only the AAAA answer"],
  ["Static neighbour entries", "silent drop, not “unreachable”"],
  ["gai.conf per namespace", "lab address order; host untouched"],
];
why.forEach(([a, b], i) => {
  const y = Y0 + i * 1.04;
  dot(s, "", 7.82, y + 0.1, 0.24);
  text(s, a, { x: 8.35, y, w: 4.4, h: 0.4, bold: true });
  text(s, b, { x: 8.35, y: y + 0.38, w: 4.4, h: 0.4, color: MUTED });
});
notes(s, "60s", "2:00-3:00", [
  ["20s", "Two Linux network namespaces on one host: hl-client runs the client and the capture, hl-server runs nginx and our DNS. IPv6 and IPv4 each get their own veth link, so we can break one family without touching the other; DNS has a third link that is never impaired."],
  ["20s", "The key choice: impairments sit only on the server end - netem for server-to-client, and an ifb device for client-to-server. The client's interfaces carry no qdisc, so tcpdump sees each SYN at the moment it is sent. Put netem on the client and dropped SYNs would vanish from the capture."],
  ["20s", "Static neighbour entries make a blackhole a silent drop, as on a real broken path, not an ARP failure. Our DNS can delay one record type, which is how S6 delays only AAAA. And the client gets its own gai.conf inside the namespace; the host's settings are never touched."],
], "baseline is 10 ms each way: 20 ms RTT, measured before every run.");

// 5. Method and evidence discipline (Implementation)
S = sec("Implementation");
s = content();
title(s, "Why the numbers can be trusted");
const tags = [
  ["Packet-level (pcap)", "seen on the wire in the client namespace"],
  ["Client log", "what curl -w or the NetLog reported"],
  ["Derived (pcap − lab RTT)", "packets combined with the pre-run ping"],
  ["Interpretation", "our reading; never a measurement"],
];
tags.forEach(([a, b], i) => {
  const y = Y0 + 0.05 + i * 0.98;
  tag(s, a, 0.6, y, 3.3);
  text(s, b, { x: 4.15, y: y - 0.02, w: 3.8, h: 0.8 });
});
text(s, "On these slides, an untagged result is packet-level.", { x: 0.6, y: 5.65, w: 7.3, h: 0.8, bold: true });
card(s, 8.3, Y0, 4.45, 5.2);
panelTitle(s, "A certified dataset", 8.6, Y0 + 0.2, 3.9);
text(s, [
  { text: "lists its exact sessions in a manifest", options: { bullet: true, breakLine: true } },
  { text: "verify passed before and after every run", options: { bullet: true, breakLine: true } },
  { text: "every capture complete, hash in its record", options: { bullet: true, breakLine: true } },
  { text: "zero cross-check conflicts", options: { bullet: true } },
], { x: 8.6, y: Y0 + 0.75, w: 3.95, h: 2.9, paraSpaceAfter: 8 });
text(s, "The analysis refuses anything else. Nothing is skipped or filled in.", { x: 8.6, y: 5.3, w: 3.95, h: 1.2, bold: true });
notes(s, "40s", "3:00-3:40", [
  ["20s", "Every claim carries one of four evidence tags. Packet-level means we saw it on the wire. Client log is what the client said about itself. Derived combines the packets with our ping measurement. Interpretation is our reading and is never presented as a measurement. Untagged numbers on these slides are packet-level."],
  ["20s", "A certified dataset is an exact list of sessions where every run passed lab verification before and after, every capture is complete and hashed, and client and capture agree. The analysis refuses to run on anything that fails those checks - it stops, it does not skip."],
], "zero cross-check conflicts in the 280-run core.");

// 6. Demo
s = content();
title(s, "Live demo: one IPv6-blackhole run, start to finish");
const steps = [
  ["1", "Verify the lab", "real RTT on both links; PASS or FAIL"],
  ["2", "Run curl once in S1", "IPv6 blackholed; capture running"],
  ["3", "See the race", "race timeline, then large numbers"],
];
steps.forEach(([k, a, b], i) => {
  const y = Y0 + 0.05 + i * 1.2;
  dot(s, k, 0.6, y, 0.5);
  text(s, a, { x: 1.35, y: y - 0.04, w: 5.8, h: 0.4, bold: true });
  text(s, b, { x: 1.35, y: y + 0.36, w: 5.8, h: 0.4, color: MUTED });
});
card(s, 7.6, Y0, 5.15, 3.65);
panelTitle(s, "Watch for", 7.9, Y0 + 0.2, 4.6);
text(s, [
  { text: "the IPv6 SYN that gets no answer", options: { bullet: true, breakLine: true } },
  { text: "the IPv4 SYN about 200 ms later", options: { bullet: true, breakLine: true } },
  { text: "IPv4 winning the race", options: { bullet: true, breakLine: true } },
  { text: "verify passing again afterwards", options: { bullet: true } },
], { x: 7.9, y: Y0 + 0.75, w: 4.7, h: 2.7, paraSpaceAfter: 6 });
text(s, "A live run is a demonstration. It is not part of any dataset, and its numbers will differ slightly from the report.",
     { x: 0.6, y: 5.6, w: 12.15, h: 0.7, fontSize: PT.second, color: MUTED });
notes(s, "3m40s (20s slide + 3m20s terminal)", "3:40-7:20", [
  ["20s", "Set it up from the slide: three steps, and four things to watch. Then switch to the terminal. The lab is already built (sudo src/lab/setup.sh, run before the talk), and make demo-check passed on this machine at the venue."],
  ["60s", "Type make demo. One command, under a minute of machine time; talk over it. Step 1 verifies the lab: point at the measured RTT on each link - about 21 ms - and the PASS. Say: we measure the real RTT; netem settings are not ground truth. Step 2 runs curl once in S1; read the progress lines as they appear: it applies the blackhole, verifies it is 100% loss with no ICMP errors, captures, runs curl, restores the baseline and verifies again."],
  ["60s", "Step 3 re-reads the capture and checks it against the run record; step 4 opens the connection race timeline in the browser. Point at the IPv6 SYN with no reply, the IPv4 SYN about 200 ms later, the inter-family delay arrow between them, and IPv4 winning."],
  ["60s", "Back to the terminal for the large numbers: winning family, each family's first SYN, the inter-family attempt delay, TCP setup time (around 222 ms), the oracle and the cost of racing. Say which are packet-level and which are derived. The lab stays up at baseline, so if a judge asks for another cell: make demo SCENARIO=S4 CLIENT=chromium."],
  ["20s", "Back to the slides. If anything fails live, make demo prints FAIL, puts the lab back to its baseline and verifies it. Fallback: the committed example runs in examples/ show the same thing. After the talk: sudo src/lab/teardown.sh, then verify the teardown."],
], "about 201 ms from the first IPv6 SYN to the IPv4 SYN (200.956 ms median in the core).");

// 7. Core results (Impact)
S = sec("Impact");
s = content();
title(s, "Core results: winner and median TCP setup");
const hdr = (t) => ({ text: t, options: { bold: true, color: "FFFFFF", fill: { color: BLUE } } });
const win = (fam, v) => ({ text: `${fam} · ${v} ms`, options: { bold: fam === "IPv4" } });
const rows = [
  [hdr("Cell"), hdr("Condition"), hdr("curl"), hdr("Chromium")],
  ["C0", "healthy baseline", win("IPv6", n("curl_C0")), win("IPv6", n("chr_C0"))],
  ["S1", "IPv6 blackhole", win("IPv4", n("curl_S1")), win("IPv4", n("chr_S1"))],
  ["S2", "IPv6 +600 ms RTT", win("IPv4", n("curl_S2")), win("IPv4", n("chr_S2"))],
  ["S3", "IPv6 +150 ms RTT", win("IPv6", n("curl_S3")), win("IPv6", n("chr_S3"))],
  ["S4", "IPv4 blackhole", win("IPv6", n("curl_S4")), win("IPv6", n("chr_S4"))],
  ["S5", "IPv4 +600 ms RTT", win("IPv6", n("curl_S5")), win("IPv6", n("chr_S5"))],
  ["S6", "AAAA answer +300 ms", win("IPv6", n("curl_S6")), win("IPv6", n("chr_S6"))],
];
table(s, rows, { colW: [1.15, 3.6, 3.7, 3.7] });
text(s, `20 runs per cell. S6: the 300 ms shows up in DNS time (${n("curl_S6_dns")} / ${n("chr_S6_dns")} ms), not in TCP setup, which starts at the first SYN. Every run: HTTP 200 (${n("http_ok")}, client log).`,
     { x: 0.6, y: 5.85, w: 12.15, h: 0.75, fontSize: PT.second });
notes(s, "40s", "7:20-8:00", [
  ["20s", "The PS-028 core: seven conditions, two clients, twenty runs each. Read the IPv4 rows: when IPv6 is blackholed or 600 ms slow, IPv4 wins every run, and setup takes about 222 ms for curl and about 322 ms for Chromium. When IPv6 is only 150 ms slower, IPv6 still wins, in about 171 ms."],
  ["20s", "S4 and S5: IPv4 impaired makes no difference because IPv6 is tried first and wins; no IPv4 SYN was sent at all. S6 is the trap: the delayed AAAA answer appears in DNS time, about 302 ms, not in TCP setup. Always quote both for S6."],
], `curl S1 ${n("curl_S1")} ms against Chromium S1 ${n("chr_S1")} ms - about 100 ms apart.`);

// 8. Cost of racing (headline)
s = content();
title(s, "Headline: the cost of racing");
img(s, "oracle", 0.45, Y0, "TCP setup against the oracle: median per cell against IPv6 RTT, both clients, latency-sweep");
const sx2 = 7.25;
tag(s, "Derived (pcap − lab RTT)", sx2, Y0 + 0.05, 3.3);
text(s, "When IPv6 fails, IPv4 wins; racing costs", { x: sx2, y: 2.15, w: 5.5, h: 0.4, bold: true });
curlMark(s, sx2, 2.95);
text(s, "≈ 201 ms", { x: sx2 + 0.42, y: 2.7, w: 3.0, h: 0.75, fontSize: 40, bold: true, color: CURL });
text(s, `curl, cell medians ${n("curl_cost_v4")}`, { x: sx2 + 0.42, y: 3.42, w: 5.1, h: 0.35, fontSize: PT.second });
chrMark(s, sx2, 4.15);
text(s, "≈ 301 ms", { x: sx2 + 0.42, y: 3.9, w: 3.0, h: 0.75, fontSize: 40, bold: true, color: CHR });
text(s, `Chromium, cell medians ${n("chr_cost_v4")}`, { x: sx2 + 0.42, y: 4.62, w: 5.1, h: 0.35, fontSize: PT.second });
card(s, sx2, 5.2, 5.5, 1.6);
text(s, `When IPv6 wins: within ${n("cost_v6_bound")} of zero`, { x: sx2 + 0.25, y: 5.33, w: 5.0, h: 0.4, fontSize: PT.sub, bold: true, color: BLUE });
text(s, "Below the 1 ms resolution of the ping behind the oracle: below what we can resolve, not zero.",
     { x: sx2 + 0.25, y: 5.78, w: 5.0, h: 0.9, fontSize: PT.second });
notes(s, "60s", "8:00-9:00", [
  ["20s", "This is the headline. The oracle is a hindsight reference: the setup time you would get if you had connected straight to the family that won, using that family's measured ping RTT. Cost of racing is our setup time minus that. It is a derived value, packets minus ping."],
  ["20s", "When IPv6 fails and IPv4 has to win, racing costs about 201 ms for curl and about 301 ms for Chromium - cell medians 200.76 to 201.48 and 300.43 to 302.17 ms in the latency sweep. That is the price of waiting before trying IPv4."],
  ["20s", "When IPv6 wins, every cell is within 0.9 ms of zero. Careful wording: above 100 ms the ping prints whole milliseconds, so the cost is below what our reference can resolve. Do not say it is zero. Source is the latency-sweep campaign, 180 runs; in many of those IPv6 cells no IPv4 attempt was made at all, and where one was (curl -0.19 to +0.73, Chromium -0.44 to +0.28 ms) the result is the same."],
], "about 201 ms (curl) and 301 ms (Chromium) when IPv6 fails; under 1 ms - unresolvable - when IPv6 wins.");

// 9. IPv6 latency budget
s = content();
title(s, "How slow can IPv6 get before IPv4 wins?");
img(s, "budget", 0.45, Y0, "IPv6 win fraction and TCP setup against IPv6 RTT for curl and Chromium, latency-sweep and jitter cells");
const bx = 10.2;
curlMark(s, bx, Y0 + 0.17);
text(s, "curl", { x: bx + 0.38, y: Y0 + 0.07, w: 2.0, h: 0.45, bold: true });
text(s, `flip\n${n("curl_flip")}\nT = ${n("curl_T_ls")} ms`, { x: bx, y: Y0 + 0.6, w: 2.6, h: 1.2 });
chrMark(s, bx, 3.85);
text(s, "Chromium", { x: bx + 0.38, y: 3.75, w: 2.2, h: 0.45, bold: true });
text(s, `flip\n${n("chr_flip")}\nT = ${n("chr_T_ls")} ms`, { x: bx, y: 4.28, w: 2.6, h: 1.2 });
text(s, "latency-sweep, 5 ms steps, n = 5 per cell", { x: bx, y: 6.2, w: 2.6, h: 0.55, fontSize: PT.caption, color: MUTED });
notes(s, "60s", "9:00-10:00", [
  ["20s", "Here we slowed IPv6 in 5 ms steps and kept IPv4 healthy. Top row: the share of runs IPv6 won. Every sweep cell was unanimous, 5 out of 5 one way or the other, so the outcome flips cleanly."],
  ["20s", "curl flips between 221 and 226 ms of IPv6 RTT; Chromium between 321 and 326. T is the time from the first SYN to the IPv4 SYN-ACK, read straight from the packets: 221.84 ms for curl and 321.99 for Chromium in this campaign. Each T sits inside its own flip bracket - two independent methods agree."],
  ["20s", "So IPv6 keeps winning as long as its RTT stays below about T: roughly 221 ms for curl and 321 ms for Chromium, in this lab. Bottom row: setup time climbs with the IPv6 RTT until the flip, then stays flat at T, because IPv4 is winning there. The diamonds are the jitter cells; they come on a later slide."],
], `T = ${n("curl_T_ls")} ms (curl) and ${n("chr_T_ls")} ms (Chromium), latency-sweep - always say the campaign.`);

// 10. Timeout sweep
s = content();
title(s, "curl's timeout: T tracks timeout + IPv4 handshake");
img(s, "he", 0.45, Y0, "curl T against configured --happy-eyeballs-timeout-ms, with residual panel, he-sweep S1");
const hx = 10.2;
text(s, "8 curl variants, 50 to 500 ms, IPv6 blackholed", { x: hx, y: Y0 + 0.05, w: 2.6, h: 1.1, bold: true });
text(s, `T runs ${n("he_resid_all")} late in every variant`, { x: hx, y: 2.95, w: 2.6, h: 1.1 });
text(s, "A step between 250 and 300 ms that we cannot explain", { x: hx, y: 4.35, w: 2.6, h: 1.1 });
text(s, "he-sweep, n = 10 per cell", { x: hx, y: 6.2, w: 2.6, h: 0.35, fontSize: PT.caption, color: MUTED });
notes(s, "40s", "10:00-10:40", [
  ["20s", "Plain curl doesn't let us see its timeout, so we set it: eight values from 50 to 500 ms, with IPv6 blackholed. The prediction was written down before the run: T should be the timeout plus the IPv4 handshake. It tracks that line across the whole range."],
  ["20s", "Say tracks, not equals: it runs 0.69 to 1.99 ms late in every variant, in two groups, with a step between 250 and 300 that we do not explain. The residual panel is shown as measured, uneven as it is. Control: curl with 200 set explicitly sent its IPv4 SYN at 200.833 ms, plain curl at 200.832."],
], `${n("he_resid_all")} late - 'tracks', never 'equals'.`);

// 11. Jitter
s = content();
title(s, "With jitter, the winner becomes a probability");
const jrows = [
  [hdr("Client"), hdr("IPv6 jitter cell"), hdr("Model"), hdr("Observed, 95% Wilson")],
  ["curl", "±50 ms each way", n("j_curl50_pred").replace(/[| ]/g, ""), n("j_curl50_obs")],
  ["curl", "±70 ms each way", n("j_curl70_pred").replace(/[| ]/g, ""), n("j_curl70_obs")],
  ["Chromium", "±50 ms each way", n("j_chr50_pred").replace(/[| ]/g, ""), n("j_chr50_obs")],
  ["Chromium", "±70 ms each way", n("j_chr70_pred").replace(/[| ]/g, ""), n("j_chr70_obs")],
];
table(s, jrows, { colW: [2.0, 3.3, 1.6, 5.25] });
tag(s, "Interpretation", 0.6, 4.45, 2.2);
text(s, "Model: P(IPv6 wins) = Φ((T − μ)/σ). All four cells match within their Wilson intervals.", { x: 3.05, y: 4.45, w: 9.7, h: 0.75 });
text(s, [
  { text: `Inputs measured independently of the outcomes: T from the no-jitter twins (${n("curl_T_jl")} / ${n("chr_T_jl")} ms, jitter-loss), μ and σ from the verify pings.`, options: { bullet: true, breakLine: true } },
  { text: "Written up together with the results, so not a pre-registered prediction. Its T values were fixed before the latency sweep, which then confirmed them.", options: { bullet: true } },
], { x: 0.6, y: 5.3, w: 12.15, h: 1.5, paraSpaceAfter: 6 });
notes(s, "40s", "10:40-11:20", [
  ["20s", "Add jitter to IPv6 and the outcome is no longer all or nothing: each run's IPv6 handshake time is random, and the winner depends on whether it beats T. We report win fractions with 95% Wilson intervals."],
  ["20s", "A simple normal model matches all four cells within their intervals. Its inputs were measured separately from the outcomes: T from the no-jitter twins, 221.96 and 322.47 ms in the jitter-loss campaign, and the spread from the verify pings. Be precise: the model was committed with its results, so do not call it a prediction made in advance. What was fixed in advance is T, and the later latency sweep confirmed it."],
], `T from the jitter-loss twins: ${n("curl_T_jl")} ms (curl), ${n("chr_T_jl")} ms (Chromium).`);

// 12. What the packets corrected
s = content();
title(s, "What the packets corrected");
card(s, 0.6, Y0, 4.3, 4.25);
panelTitle(s, "We predicted: it doubles", 0.9, Y0 + 0.2, 3.8);
text(s, `A doubling timer: SYNs at ${n("rto_pred_times")}, so gaps of about 1, 2 and 4 s.`, { x: 0.9, y: Y0 + 0.75, w: 3.75, h: 1.4 });
text(s, "Committed to the findings doc on 21 Nov 2026 at 18:02 UTC, with results pending, before the campaign's first session.",
     { x: 0.9, y: Y0 + 2.4, w: 3.75, h: 1.4, fontSize: PT.second, color: MUTED });
text(s, "The captures showed: gap to the next SYN on the same socket (Gv6c30)", { x: 5.2, y: Y0, w: 7.55, h: 0.75, bold: true });
const g = (k) => n(k).replace("median ", "");
const rto = [
  [hdr("Retransmission"), hdr("curl"), hdr("Chromium")],
  ["1st", g("rto_curl_1"), g("rto_chr_1")],
  ["2nd", g("rto_curl_2"), g("rto_chr_2")],
  ["3rd", g("rto_curl_3"), g("rto_chr_3")],
  ["4th", g("rto_curl_4"), "none"],
];
table(s, rto, { x: 5.2, y: 2.35, w: 7.55, colW: [2.55, 2.5, 2.5] });
text(s, "About 1 s every time, up to the fifth SYN.", { x: 5.2, y: 5.2, w: 7.55, h: 0.4, bold: true });
tag(s, "Interpretation", 0.6, 6.1, 2.2);
text(s, "matches net.ipv4.tcp_syn_linear_timeouts = 4 in hl-client", { x: 3.05, y: 6.1, w: 9.7, h: 0.42, valign: "middle" });
notes(s, "40s", "11:20-12:00", [
  ["20s", "Our favourite result, because we got it wrong first. In the compound control - IPv4 blackholed and 30% loss on IPv6, so IPv6 is the only way through - the kernel's SYN retransmissions become visible. We predicted the textbook doubling timer: 1, 2, 4 seconds. Unlike the jitter model, that prediction is in the git history before the campaign ran."],
  ["20s", "The captures said otherwise: about one second between every SYN, up to the fifth, for both clients. Our reading, labelled as interpretation, is that this matches the kernel's tcp_syn_linear_timeouts setting, which is 4 in our client namespace. We corrected the findings doc and kept the wrong prediction visible."],
], "about 1 s between SYNs (1037.0 ms first gap for curl, then 1023.9 ms) - not 1, 2, 4 s.");

// 13. Prior work
s = content();
title(s, "Prior work: we reproduce published delays");
const prow = [
  [hdr("Client"), hdr("Published CAD [3]"), hdr("Our inter-family delay, S1"), hdr("Our T (jitter-loss)")],
  ["curl", "200 ms", `${n("curl_ifd_S1")} ms`, `${n("curl_T_jl")} ms`],
  ["Chromium", "300 ms", `${n("chr_ifd_S1")} ms`, `${n("chr_T_jl")} ms`],
];
table(s, prow, { colW: [2.2, 2.9, 4.2, 2.85] });
text(s, "They published these first: a reproduction, not a discovery.", { x: 0.6, y: 3.3, w: 12.15, h: 0.4, bold: true });
card(s, 0.6, 3.95, 12.15, 2.4);
panelTitle(s, "What we add", 0.9, 4.1, 11.5);
text(s, [
  { text: "the cost of racing against an oracle baseline, not measured in that work", options: { bullet: true, breakLine: true } },
  { text: "loss and jitter, with a win-fraction model; curl's timeout set to eight values", options: { bullet: true, breakLine: true } },
  { text: "a compound control that exposes the kernel's SYN timer", options: { bullet: true, breakLine: true } },
  { text: "certified datasets with hashes; uncertified data is refused", options: { bullet: true } },
], { x: 0.9, y: 4.55, w: 11.6, h: 1.75, paraSpaceAfter: 4 });
text(s, "[3] P. Sattler et al., “Lazy Eye Inspection: Capturing the State of Happy Eyeballs Implementations”, ACM IMC 2025 (arXiv 2412.00263).",
     { x: 0.6, y: 6.5, w: 12.15, h: 0.3, fontSize: PT.caption, color: MUTED });
notes(s, "40s", "12:00-12:40", [
  ["20s", "Sattler and colleagues at TUM published curl's Connection Attempt Delay as 200 ms and Chromium-based browsers' as 300 ms. Our core data shows curl's IPv4 SYN 200.956 ms and Chromium's 301.067 ms after the first IPv6 SYN; T, which adds the IPv4 handshake, is 221.96 and 322.47 ms in jitter-loss. We reproduce their values independently; we did not discover them."],
  ["20s", "What we add is on the slide. If asked about internals: their paper says neither client implements the Resolution Delay - that is their claim, not ours; we only report packets. One refinement: they report one IPv6 and one IPv4 address tried; we see Chromium send a second IPv6 SYN to the same address from a new port, median 250.625 ms in S1, in 40 of 40 runs - one address, two attempts. Open question we cannot answer: whether the HEv3 behaviour they describe behind a Chromium flag is now on by default."],
], "reproduction, not discovery: 200 ms and 300 ms are theirs; 200.956 and 301.067 ms are ours.");

// 14. Limitations and what next
s = content();
title(s, "Limitations, and what we would do next");
card(s, 0.6, Y0, 6.0, 5.2);
card(s, 6.95, Y0, 5.8, 5.2);
panelTitle(s, "What these data cannot show", 0.9, Y0 + 0.2, 5.4);
text(s, [
  { text: "one lab, one host, one kernel", options: { bullet: true, breakLine: true } },
  { text: "synthetic netem impairments, not carrier measurements", options: { bullet: true, breakLine: true } },
  { text: "plain HTTP: no TLS, QUIC or SVCB", options: { bullet: true, breakLine: true } },
  { text: "two clients, one version each", options: { bullet: true, breakLine: true } },
  { text: "one AAAA and one A: not how many addresses a client would try", options: { bullet: true } },
], { x: 0.9, y: Y0 + 0.75, w: 5.45, h: 4.25, paraSpaceAfter: 10 });
panelTitle(s, "With more time", 7.25, Y0 + 0.2, 5.2);
text(s, [
  { text: "repeat on a second host and kernel", options: { bullet: true, breakLine: true } },
  { text: "several AAAA and A records per name", options: { bullet: true, breakLine: true } },
  { text: "delay the A answer, the counterpart of S6", options: { bullet: true, breakLine: true } },
  { text: "TLS, QUIC and HTTPS/SVCB records", options: { bullet: true, breakLine: true } },
  { text: "more clients and versions; share the data with the IETF HAPPY working group", options: { bullet: true } },
], { x: 7.25, y: Y0 + 0.75, w: 5.25, h: 4.25, paraSpaceAfter: 10 });
notes(s, "40s", "12:40-13:20", [
  ["20s", "Limits, plainly: one lab on one host and kernel, synthetic impairments - mobile-inspired latency conditions, not carrier measurements - plain HTTP only, two clients at one version each. And our DNS returns one IPv6 and one IPv4 address, so we cannot say how many addresses a client would try."],
  ["20s", "Next: a second host and kernel; names with several addresses; delaying the A answer instead of AAAA, which would address the open S6 question; TLS, QUIC and SVCB; more clients. Everything is in the repository - code, report and the certified datasets. Thank you."],
], "1,328 runs, all from one host - say it as a limit, not just a boast.");

// 15. References (the proposal's bibliography page: numbered entries on one panel)
S = sec("References");
s = content();
title(s, "References");
const refs = [
  "D. Schinazi, T. Pauly. Happy Eyeballs Version 2: Better Connectivity Using Concurrency. RFC 8305, IETF, December 2017. (reference design)",
  "T. Pauly et al. Happy Eyeballs Version 3. draft-ietf-happy-happyeyeballs-v3-04, pinned at -04; background only, no conformance claimed.",
  "P. Sattler et al. Lazy Eye Inspection: Capturing the State of Happy Eyeballs Implementations. ACM IMC 2025, doi:10.1145/3730567.3732925.",
  "V. Bajpai, J. Schönwälder. Measuring the Effects of Happy Eyeballs. ACM/IRTF/ISOC ANRW 2016.",
  "curl documentation: --happy-eyeballs-timeout-ms (documented default 200 ms).",
  "Happy Eyeballs Webtester, happy-eyeballs.net.",
];
card(s, 0.6, Y0, 12.15, 5.2);
let ry = Y0 + 0.3;
refs.forEach((r, i) => {
  const h = r.length > 125 ? 0.62 : 0.32;   // two lines or one at 16 pt across 11.0 in
  text(s, `[${i + 1}]`, { x: 0.9, y: ry, w: 0.6, h: 0.32, fontSize: PT.second, bold: true, color: BLUE });
  text(s, r, { x: 1.5, y: ry, w: 11.0, h, fontSize: PT.second });
  ry += h + 0.22;
});
notes(s, "10s", "13:20-13:30", [
  ["10s", "Everything we cite is here; our curl and Chromium delays reproduce Sattler et al."],
], "[3] Sattler et al., IMC 2025: the 200 ms and 300 ms we reproduce.");

// 16. Thank you (the proposal's closing page: the title page's layout, with the race illustration)
s = pres.addSlide({ masterName: "TITLE", sectionTitle: S });
s.addImage({ path: path.join(__dirname, "assets", "aiori_logo.png"), x: 0.6, y: 0.45, w: 1.2, h: 1.2 * 119 / 120,
             altText: "AIORI logo" });
text(s, "Thank You for Your Attention!", { x: 0.6, y: 2.0, w: 7.0, h: 1.6, fontSize: 44, bold: true, color: BLUE });
text(s, "Questions?", { x: 0.6, y: 3.7, w: 7.0, h: 0.55, fontSize: 28 });
text(s, "NetDefenders · A3-PS028-TC278", { x: 0.6, y: 4.75, w: 7.0, h: 0.4, bold: true });
text(s, "happylab-aiori-ps-028.vercel.app", { x: 0.6, y: 5.2, w: 7.0, h: 0.35, fontSize: PT.second, color: BLUE });
race(s);
notes(s, "5s, then questions", "13:30-13:35", [
  ["5s", "Thank you. We are happy to take questions."],
], "1,328 runs, 280 of them the PS-028 core.");

// ---- write ---------------------------------------------------------------------------------
module.exports = { FIGURES };
if (require.main === module) {
  const out = path.join(__dirname, "HappyLab_PS028_TC278.pptx");
  pres.writeFile({ fileName: out }).then((f) => {
    // pptxgenjs writes directory entries into the ZIP; cloud viewers refuse them.
    require("child_process").execFileSync("zip", ["-dq", f, "*/"]);
    console.log("wrote", f);
  });
}
