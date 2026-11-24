// HappyLab presentation deck (AIORI-3 PS-028, team NetDefenders, A3-PS028-TC278).
//
//   cd deck && npm ci && node build_deck.js       # writes HappyLab_PS028_TC278.pptx
//
// Every measured number comes from deck_numbers.json (each one is checked verbatim against its
// source doc by src/tests/test_deck.py). Every figure comes from docs/figures/ as exported; nothing
// is re-plotted. The test also fails if a figure named in FIGURES is missing.

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
  oracle: "docs/figures/fig1_setup_vs_oracle_half.png",
  budget: "docs/figures/fig1_ipv6_latency_budget_full.png",
  he: "docs/figures/fig2_he_linearity_full.png",
};
const fig = (k) => path.join(REPO, FIGURES[k]);

// ---- theme ---------------------------------------------------------------------------------
const INK = "14202B";      // body text, near-black navy
const MUTED = "3D4852";    // secondary text, still >= 9:1 on white
const PANEL = "EEF2F5";    // card fill
const LINE = "5B6670";     // borders and diagram lines
const ACCENT = "0B5C6B";   // dark teal: headings inside cards, stat numbers
const CURL = "1F66B8";     // matches the figures' curl blue (always with a circle)
const CHR = "B4461C";      // darker than the figures' orange so text passes contrast (always with a triangle)
const FONT = "Arial";      // metric-identical Liberation Sans in the PDF renderer; ships with Office

const pres = new pptxgen();
pres.layout = "LAYOUT_WIDE"; // 13.333 x 7.5 in
pres.title = "HappyLab: Happy Eyeballs IPv4/IPv6 fallback measurement (PS-028)";
pres.author = "Team NetDefenders";
pres.theme = { headFontFace: FONT, bodyFontFace: FONT };
const W = 13.333;

pres.defineSlideMaster({
  title: "CONTENT",
  background: { color: "FFFFFF" },
  objects: [
    { text: { text: "HappyLab · PS-028 · Team NetDefenders (A3-PS028-TC278)",
              options: { x: 0.6, y: 7.0, w: 8, h: 0.35, fontFace: FONT, fontSize: 14, color: MUTED } } },
  ],
  slideNumber: { x: 12.2, y: 7.0, w: 0.6, h: 0.35, fontFace: FONT, fontSize: 14, color: MUTED, align: "right" },
  placeholders: [],
});
pres.defineSlideMaster({ title: "TITLE", background: { color: "FFFFFF" }, objects: [] });

// ---- helpers -------------------------------------------------------------------------------
function title(s, text) {
  s.addText(text, { x: 0.6, y: 0.3, w: W - 1.2, h: 0.9, fontFace: FONT, fontSize: 36, bold: true,
                    color: INK, valign: "middle", margin: 0, isTextBox: true });
}
function text(s, t, o) {
  s.addText(t, Object.assign({ fontFace: FONT, fontSize: 24, color: INK, valign: "top", margin: 0,
                               isTextBox: true }, o));
}
// Evidence tag chip: the label is always written out, so no tag relies on colour.
function tag(s, label, x, y, w) {
  s.addText(label, { shape: pres.ShapeType.roundRect, rectRadius: 0.08, x, y, w: w || 3.6, h: 0.5,
                     fill: { color: "FFFFFF" }, line: { color: INK, width: 1.5 }, fontFace: FONT,
                     fontSize: 20, bold: true, color: INK, align: "center", valign: "middle", margin: 0 });
}
function card(s, x, y, w, h) {
  s.addShape(pres.ShapeType.roundRect, { x, y, w, h, rectRadius: 0.1, fill: { color: PANEL },
                                         line: { color: PANEL } });
}
// Client markers repeat the figures' encoding: curl = circle, Chromium = triangle.
function curlMark(s, x, y, d = 0.28) {
  s.addShape(pres.ShapeType.ellipse, { x, y, w: d, h: d, fill: { color: CURL }, line: { color: INK, width: 1 } });
}
function chrMark(s, x, y, d = 0.3) {
  s.addShape(pres.ShapeType.triangle, { x, y, w: d, h: d * 0.9, fill: { color: CHR }, line: { color: INK, width: 1 } });
}
function notes(s, budget, clock, beats, remember) {
  const lines = [`TIME: ${budget} (clock ${clock})`, ""];
  for (const [t, say] of beats) lines.push(`[${t}] ${say}`, "");
  lines.push(`NUMBER NOT TO FORGET: ${remember}`);
  s.addNotes(lines.join("\n"));
}
function sec(name) { pres.addSection({ title: name }); return name; }
function img(s, key, x, y, h, aspect, alt) {
  s.addImage({ path: fig(key), x, y, h, w: h * aspect, altText: alt });
}

// =============================================================================================
// 1. Title (Problem)
let S = sec("Problem");
let s = pres.addSlide({ masterName: "TITLE", sectionTitle: S });
text(s, "AIORI-3 · PS-028 · Team NetDefenders · A3-PS028-TC278", { x: 0.8, y: 0.8, w: 11.5, h: 0.5, color: MUTED });
text(s, "HappyLab", { x: 0.8, y: 1.5, w: 11.5, h: 1.3, fontSize: 66, bold: true, color: INK });
text(s, "Happy Eyeballs IPv4/IPv6 Fallback Measurement", { x: 0.8, y: 2.85, w: 12.0, h: 0.7, fontSize: 32, color: ACCENT, bold: true });
text(s, "A controlled dual-stack lab that measures, from packet captures, how curl and Chromium race IPv6 against IPv4 when one path fails or slows.",
     { x: 0.8, y: 3.75, w: 11.6, h: 1.1, fontSize: 26 });
// motif: the race, two lanes
const laneY = [5.45, 6.2];
text(s, "IPv6", { x: 0.8, y: laneY[0] - 0.05, w: 1.0, h: 0.45, bold: true });
text(s, "IPv4", { x: 0.8, y: laneY[1] - 0.05, w: 1.0, h: 0.45, bold: true });
s.addShape(pres.ShapeType.line, { x: 1.9, y: laneY[0] + 0.18, w: 3.2, h: 0, line: { color: LINE, width: 3, dashType: "dash" } });
text(s, "SYN … no answer", { x: 5.25, y: laneY[0] - 0.05, w: 3.4, h: 0.45, color: MUTED });
s.addShape(pres.ShapeType.line, { x: 3.4, y: laneY[1] + 0.18, w: 4.6, h: 0, line: { color: INK, width: 4, endArrowType: "triangle" } });
text(s, "connected", { x: 8.2, y: laneY[1] - 0.05, w: 2.2, h: 0.45, bold: true });
text(s, "Sam Rajeev · Pranav Murali\nMentor: Dr. Monika Puttaramaiah", { x: 8.6, y: 5.35, w: 4.2, h: 1.0, fontSize: 18, color: MUTED, align: "right" });
notes(s, "20s", "0:00-0:20", [
  ["20s", "We are NetDefenders, problem statement PS-028. HappyLab is a lab that measures, from the packets, how two real clients - curl and Chromium - race IPv6 against IPv4 when one path is broken or slow."],
], "none yet - just the name: HappyLab, PS-028.");

// 2. The problem
s = pres.addSlide({ masterName: "CONTENT", sectionTitle: S });
title(s, "A broken IPv6 path makes every connection wait");
text(s, [
  { text: "Dual-stack hosts get an AAAA and an A answer, and usually try IPv6 first.", options: { bullet: true, breakLine: true } },
  { text: "If the IPv6 path is broken or slow, that first SYN goes unanswered.", options: { bullet: true, breakLine: true } },
  { text: "Happy Eyeballs (RFC 8305) bounds the wait: after a short delay, also try IPv4, and keep whichever handshake completes first.", options: { bullet: true } },
], { x: 0.6, y: 1.45, w: 6.6, h: 3.9, paraSpaceAfter: 14 });
// diagram: what the client does while it waits
card(s, 7.6, 1.45, 5.15, 3.9);
text(s, "While the client waits", { x: 7.85, y: 1.6, w: 4.7, h: 0.45, bold: true, color: ACCENT });
const dy = [2.45, 3.45, 4.45];
text(s, "IPv6 SYN", { x: 7.85, y: dy[0], w: 1.7, h: 0.45, bold: true });
s.addShape(pres.ShapeType.line, { x: 9.6, y: dy[0] + 0.22, w: 2.9, h: 0, line: { color: LINE, width: 3, dashType: "dash" } });
text(s, "no reply", { x: 10.6, y: dy[0] + 0.32, w: 1.9, h: 0.4, fontSize: 20, color: MUTED });
text(s, "wait", { x: 7.85, y: dy[1], w: 1.7, h: 0.45, bold: true });
s.addShape(pres.ShapeType.line, { x: 9.6, y: dy[1] + 0.22, w: 2.9, h: 0, line: { color: INK, width: 3, beginArrowType: "triangle", endArrowType: "triangle" } });
text(s, "how long?", { x: 10.4, y: dy[1] + 0.32, w: 2.1, h: 0.4, fontSize: 20, color: MUTED });
text(s, "IPv4 SYN", { x: 7.85, y: dy[2], w: 1.7, h: 0.45, bold: true });
s.addShape(pres.ShapeType.line, { x: 9.6, y: dy[2] + 0.22, w: 2.9, h: 0, line: { color: INK, width: 4, endArrowType: "triangle" } });
text(s, "wins", { x: 10.8, y: dy[2] + 0.32, w: 1.7, h: 0.4, fontSize: 20, bold: true });
s.addText("What does racing actually cost, measured from the packets?", {
  shape: pres.ShapeType.roundRect, rectRadius: 0.1, x: 0.6, y: 5.65, w: 12.15, h: 1.05, fill: { color: "FFFFFF" },
  line: { color: ACCENT, width: 2.5 }, fontFace: FONT, fontSize: 30, bold: true, color: ACCENT, align: "center", valign: "middle" });
notes(s, "60s", "0:20-1:20", [
  ["20s", "On a dual-stack host the resolver returns both an IPv6 and an IPv4 address, and IPv6 is normally tried first. If that path is broken or very slow, the SYN just goes unanswered."],
  ["20s", "Happy Eyeballs, RFC 8305, limits the damage: after a short delay the client also opens an IPv4 attempt and keeps whichever handshake finishes first. RFC 8305 is our reference design, not a predictor of exact times."],
  ["20s", "So the question we set out to answer is the one at the bottom: what does that racing actually cost a real client, measured from the packets, not from configuration?"],
], "no number - the question: what does racing actually cost?");

// 3. What PS-028 asked for, and what we built (Approach)
S = sec("Approach");
s = pres.addSlide({ masterName: "CONTENT", sectionTitle: S });
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
  const y = 1.4 + i * 0.66;
  s.addText("✓", { shape: pres.ShapeType.ellipse, x: 0.6, y: y + 0.04, w: 0.46, h: 0.46, fill: { color: ACCENT },
                   line: { color: ACCENT }, fontFace: "Segoe UI Symbol", fontSize: 20, bold: true, color: "FFFFFF",
                   align: "center", valign: "middle", margin: 0 });
  text(s, a, { x: 1.25, y, w: 4.0, h: 0.55, bold: true, valign: "middle" });
  text(s, b, { x: 5.4, y, w: 7.4, h: 0.55, fontSize: 22, valign: "middle" });
});
const stats = [["1,328", "runs, all certified"], ["5", "certified datasets"], ["670", "tests, 24 Nov 2026"]];
stats.forEach(([v, k], i) => {
  const x = 0.6 + i * 4.1;
  card(s, x, 5.5, 3.85, 1.3);
  text(s, v, { x: x + 0.25, y: 5.55, w: 3.4, h: 0.7, fontSize: 40, bold: true, color: ACCENT });
  text(s, k, { x: x + 0.25, y: 6.22, w: 3.5, h: 0.5, fontSize: 20, color: INK });
});
notes(s, "40s", "1:20-2:00", [
  ["20s", "Each line here is a PS-028 requirement and what meets it. Two existing clients, six scenarios plus a healthy baseline, our own DNS, a pinned spec - RFC 8305, with the v3 draft pinned at revision 04 because it is still a draft as of today - twenty runs per cell, and a capture for every run."],
  ["20s", "Beyond the brief: 1,328 runs in total across five certified datasets - the 280-run core plus four extension campaigns - and 670 automated tests."],
], "1,328 runs (280 of them are the PS-028 core).");

// 4. Architecture
S = sec("Architecture");
s = pres.addSlide({ masterName: "CONTENT", sectionTitle: S });
title(s, "Architecture: two namespaces, three links");
// diagram
const cx = 0.6, cw = 2.35, sx = 5.0, sw = 2.35, top = 1.45, bh = 5.25;
card(s, cx, top, cw, bh);
card(s, sx, top, sw, bh);
text(s, "hl-client", { x: cx + 0.15, y: top + 0.1, w: cw - 0.3, h: 0.45, bold: true, color: ACCENT });
text(s, "hl-server", { x: sx + 0.15, y: top + 0.1, w: sw - 0.3, h: 0.45, bold: true, color: ACCENT });
text(s, "curl / Chromium\ntcpdump\nlab gai.conf", { x: cx + 0.15, y: top + 0.65, w: cw - 0.3, h: 1.3, fontSize: 20 });
text(s, "nginx\nDNS, per-type delay", { x: sx + 0.15, y: top + 0.65, w: sw - 0.3, h: 1.0, fontSize: 20 });
const links = [["v6 veth", 3.55], ["v4 veth", 4.75], ["ctl veth (DNS)", 5.95]];
links.forEach(([lab, y], i) => {
  s.addShape(pres.ShapeType.line, { x: cx + cw, y, w: sx - cx - cw, h: 0, line: { color: INK, width: 3 } });
  text(s, lab, { x: cx + cw + 0.05, y: y - 0.45, w: sx - cx - cw - 0.1, h: 0.4, fontSize: 18, align: "center" });
  if (i < 2) {
    s.addText("netem + ifb", { shape: pres.ShapeType.rect, x: sx + 0.15, y: y - 0.28, w: 2.05, h: 0.56, fill: { color: "FFFFFF" },
                               line: { color: INK, width: 1.5 }, fontFace: FONT, fontSize: 18, bold: true, color: INK,
                               align: "center", valign: "middle", margin: 0 });
    text(s, "no qdisc", { x: cx + 0.15, y: y - 0.2, w: cw - 0.3, h: 0.4, fontSize: 18, color: MUTED });
  } else {
    text(s, "never impaired", { x: sx + 0.15, y: y - 0.2, w: sw - 0.3, h: 0.4, fontSize: 18, color: MUTED });
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
  const y = 1.45 + i * 1.04;
  text(s, a, { x: 7.75, y, w: 5.1, h: 0.45, fontSize: 22, bold: true, color: ACCENT });
  text(s, b, { x: 7.75, y: y + 0.42, w: 5.1, h: 0.6, fontSize: 22 });
});
notes(s, "60s", "2:00-3:00", [
  ["20s", "Two Linux network namespaces on one host: hl-client runs the client and the capture, hl-server runs nginx and our DNS. IPv6 and IPv4 each get their own veth link, so we can break one family without touching the other; DNS has a third link that is never impaired."],
  ["20s", "The key choice: impairments sit only on the server end - netem for server-to-client, and an ifb device for client-to-server. The client's interfaces carry no qdisc, so tcpdump sees each SYN at the moment it is sent. Put netem on the client and dropped SYNs would vanish from the capture."],
  ["20s", "Static neighbour entries make a blackhole a silent drop, as on a real broken path, not an ARP failure. Our DNS can delay one record type, which is how S6 delays only AAAA. And the client gets its own gai.conf inside the namespace; the host's settings are never touched."],
], "baseline is 10 ms each way: 20 ms RTT, measured before every run.");

// 5. Method and evidence discipline (Implementation)
S = sec("Implementation");
s = pres.addSlide({ masterName: "CONTENT", sectionTitle: S });
title(s, "Why the numbers can be trusted");
const tags = [
  ["Packet-level (pcap)", "seen on the wire in the client namespace"],
  ["Client log", "what curl -w or the NetLog reported"],
  ["Derived (pcap − lab RTT)", "packets combined with the pre-run ping"],
  ["Interpretation", "our reading; never a measurement"],
];
tags.forEach(([a, b], i) => {
  const y = 1.45 + i * 1.03;
  tag(s, a, 0.6, y, 3.9);
  text(s, b, { x: 4.7, y: y - 0.02, w: 3.3, h: 0.95, fontSize: 22 });
});
text(s, "On these slides, an untagged result is packet-level.", { x: 0.6, y: 5.7, w: 7.3, h: 0.9, bold: true });
card(s, 8.3, 1.45, 4.45, 5.25);
text(s, "A certified dataset", { x: 8.55, y: 1.6, w: 4.0, h: 0.45, bold: true, color: ACCENT });
text(s, [
  { text: "lists its exact sessions in a manifest", options: { bullet: true, breakLine: true } },
  { text: "verify passed before and after every run", options: { bullet: true, breakLine: true } },
  { text: "every capture complete, hash in its record", options: { bullet: true, breakLine: true } },
  { text: "zero cross-check conflicts", options: { bullet: true } },
], { x: 8.55, y: 2.15, w: 4.0, h: 2.9, fontSize: 22, paraSpaceAfter: 8 });
text(s, "The analysis refuses anything else. Nothing is skipped or filled in.", { x: 8.55, y: 5.25, w: 4.0, h: 1.3, fontSize: 22, bold: true });
notes(s, "40s", "3:00-3:40", [
  ["20s", "Every claim carries one of four evidence tags. Packet-level means we saw it on the wire. Client log is what the client said about itself. Derived combines the packets with our ping measurement. Interpretation is our reading and is never presented as a measurement. Untagged numbers on these slides are packet-level."],
  ["20s", "A certified dataset is an exact list of sessions where every run passed lab verification before and after, every capture is complete and hashed, and client and capture agree. The analysis refuses to run on anything that fails those checks - it stops, it does not skip."],
], "zero cross-check conflicts in the 280-run core.");

// 6. Demo
s = pres.addSlide({ masterName: "CONTENT", sectionTitle: S });
title(s, "Live demo: one IPv6-blackhole run, start to finish");
const steps = [
  ["1", "Verify the lab", "real RTT on both links; PASS per check"],
  ["2", "Run curl once in S1", "IPv6 blackholed; capture running"],
  ["3", "Read the run back", "per-run table and the SYN times"],
];
steps.forEach(([k, a, b], i) => {
  const y = 1.5 + i * 1.25;
  s.addText(k, { shape: pres.ShapeType.ellipse, x: 0.6, y, w: 0.7, h: 0.7, fill: { color: ACCENT }, line: { color: ACCENT },
                 fontFace: FONT, fontSize: 28, bold: true, color: "FFFFFF", align: "center", valign: "middle", margin: 0 });
  text(s, a, { x: 1.55, y: y - 0.05, w: 5.6, h: 0.45, bold: true });
  text(s, b, { x: 1.55, y: y + 0.45, w: 5.9, h: 0.45, fontSize: 22, color: MUTED });
});
card(s, 7.6, 1.5, 5.15, 3.65);
text(s, "Watch for", { x: 7.85, y: 1.65, w: 4.7, h: 0.45, bold: true, color: ACCENT });
text(s, [
  { text: "the IPv6 SYN that gets no answer", options: { bullet: true, breakLine: true } },
  { text: "the IPv4 SYN about 200 ms later", options: { bullet: true, breakLine: true } },
  { text: "IPv4 winning the race", options: { bullet: true, breakLine: true } },
  { text: "verify passing again afterwards", options: { bullet: true } },
], { x: 7.85, y: 2.2, w: 4.75, h: 2.85, fontSize: 22, paraSpaceAfter: 6 });
text(s, "A live run is a demonstration. It is not part of any dataset, and its numbers will differ slightly from the report.",
     { x: 0.6, y: 5.35, w: 12.15, h: 1.0, fontSize: 22, color: MUTED });
notes(s, "3m40s (20s slide + 3m20s terminal)", "3:40-7:20", [
  ["20s", "Set it up from the slide: three steps, and four things to watch. Then switch to the terminal. The lab is already built (sudo src/lab/setup.sh, run before the talk)."],
  ["40s", "Step 1: sudo src/lab/verify.sh up. Point at the measured RTT on each link - about 21 ms - and the PASS lines. Say: we measure the real RTT; netem settings are not ground truth."],
  ["100s", "Step 2: sudo .venv/bin/python src/runner/orchestrate.py --scenario S1 --reps 1. While it runs: it applies the blackhole, verifies it is 100% loss with no ICMP errors, captures, runs curl, restores the baseline and verifies again. Read out the one-line summary: IPv4 won, setup time around 222 ms."],
  ["40s", "Step 3: .venv/bin/python src/analysis/summarise_session.py <session id printed by step 2>, then tcpdump -n -tt -r captures/<run id>.pcap 'tcp[tcpflags] & tcp-syn != 0'. Point at the IPv6 SYN with no reply and the IPv4 SYN about 200 ms later."],
  ["20s", "Back to the slides. Fallback if anything fails live: the committed example runs in examples/ show the same thing. After the talk: sudo src/lab/teardown.sh, then verify the teardown."],
], "about 201 ms from the first IPv6 SYN to the IPv4 SYN (200.956 ms median in the core).");

// 7. Core results (Impact)
S = sec("Impact");
s = pres.addSlide({ masterName: "CONTENT", sectionTitle: S });
title(s, "Core results: winner and median TCP setup");
const hdr = (t) => ({ text: t, options: { bold: true, color: "FFFFFF", fill: { color: INK } } });
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
s.addTable(rows, { x: 0.6, y: 1.4, w: 12.15, colW: [1.15, 3.6, 3.7, 3.7], rowH: 0.56, fontFace: FONT, fontSize: 22,
                   color: INK, border: { type: "solid", pt: 1, color: LINE }, valign: "middle", margin: [0, 0.12, 0, 0.12] });
text(s, `20 runs per cell. S6: the 300 ms shows up in DNS time (${n("curl_S6_dns")} / ${n("chr_S6_dns")} ms), not in TCP setup, which starts at the first SYN. Every run: HTTP 200 (${n("http_ok")}, client log).`,
     { x: 0.6, y: 6.1, w: 12.15, h: 0.85, fontSize: 20 });
notes(s, "40s", "7:20-8:00", [
  ["20s", "The PS-028 core: seven conditions, two clients, twenty runs each. Read the IPv4 rows: when IPv6 is blackholed or 600 ms slow, IPv4 wins every run, and setup takes about 222 ms for curl and about 322 ms for Chromium. When IPv6 is only 150 ms slower, IPv6 still wins, in about 171 ms."],
  ["20s", "S4 and S5: IPv4 impaired makes no difference because IPv6 is tried first and wins; no IPv4 SYN was sent at all. S6 is the trap: the delayed AAAA answer appears in DNS time, about 302 ms, not in TCP setup. Always quote both for S6."],
], `curl S1 ${n("curl_S1")} ms against Chromium S1 ${n("chr_S1")} ms - about 100 ms apart.`);

// 8. Cost of racing (headline)
s = pres.addSlide({ masterName: "CONTENT", sectionTitle: S });
title(s, "Headline: the cost of racing");
img(s, "oracle", 0.5, 1.3, 5.6, 1650 / 1875, "TCP setup against the oracle: median per cell against IPv6 RTT, both clients, latency-sweep");
const sx2 = 5.75;
tag(s, "Derived (pcap − lab RTT)", sx2, 1.4, 4.0);
text(s, "When IPv6 fails, IPv4 wins; racing costs", { x: sx2, y: 2.05, w: 7.0, h: 0.45, bold: true });
curlMark(s, sx2, 2.78);
text(s, "≈ 201 ms", { x: sx2 + 0.45, y: 2.55, w: 2.7, h: 0.8, fontSize: 44, bold: true, color: CURL });
text(s, `curl, cell medians ${n("curl_cost_v4")}`, { x: sx2 + 0.45, y: 3.3, w: 6.6, h: 0.45, fontSize: 22 });
chrMark(s, sx2, 4.03);
text(s, "≈ 301 ms", { x: sx2 + 0.45, y: 3.8, w: 2.7, h: 0.8, fontSize: 44, bold: true, color: CHR });
text(s, `Chromium, cell medians ${n("chr_cost_v4")}`, { x: sx2 + 0.45, y: 4.55, w: 6.6, h: 0.45, fontSize: 22 });
card(s, sx2, 5.15, 7.0, 1.7);
text(s, `When IPv6 wins: within ${n("cost_v6_bound")} of zero`, { x: sx2 + 0.25, y: 5.25, w: 6.6, h: 0.45, bold: true });
text(s, "Below the 1 ms resolution of the ping behind the oracle: below what we can resolve, not zero.",
     { x: sx2 + 0.25, y: 5.75, w: 6.6, h: 1.0, fontSize: 22 });
notes(s, "60s", "8:00-9:00", [
  ["20s", "This is the headline. The oracle is a hindsight reference: the setup time you would get if you had connected straight to the family that won, using that family's measured ping RTT. Cost of racing is our setup time minus that. It is a derived value, packets minus ping."],
  ["20s", "When IPv6 fails and IPv4 has to win, racing costs about 201 ms for curl and about 301 ms for Chromium - cell medians 200.76 to 201.48 and 300.43 to 302.17 ms in the latency sweep. That is the price of waiting before trying IPv4."],
  ["20s", "When IPv6 wins, every cell is within 0.9 ms of zero. Careful wording: above 100 ms the ping prints whole milliseconds, so the cost is below what our reference can resolve. Do not say it is zero. Source is the latency-sweep campaign, 180 runs; in many of those IPv6 cells no IPv4 attempt was made at all, and where one was (curl -0.19 to +0.73, Chromium -0.44 to +0.28 ms) the result is the same."],
], "about 201 ms (curl) and 301 ms (Chromium) when IPv6 fails; under 1 ms - unresolvable - when IPv6 wins.");

// 9. IPv6 latency budget
s = pres.addSlide({ masterName: "CONTENT", sectionTitle: S });
title(s, "How slow can IPv6 get before IPv4 wins?");
img(s, "budget", 0.4, 1.3, 5.55, 3300 / 1875, "IPv6 win fraction and TCP setup against IPv6 RTT for curl and Chromium, latency-sweep and jitter cells");
const bx = 10.3;
curlMark(s, bx, 1.6);
text(s, "curl", { x: bx + 0.4, y: 1.5, w: 2.0, h: 0.5, bold: true });
text(s, `flip\n${n("curl_flip")}\nT = ${n("curl_T_ls")} ms`, { x: bx, y: 2.05, w: 2.7, h: 1.4, fontSize: 22 });
chrMark(s, bx, 3.75);
text(s, "Chromium", { x: bx + 0.4, y: 3.65, w: 2.3, h: 0.5, bold: true });
text(s, `flip\n${n("chr_flip")}\nT = ${n("chr_T_ls")} ms`, { x: bx, y: 4.2, w: 2.7, h: 1.4, fontSize: 22 });
text(s, "latency-sweep, 5 ms steps, n = 5 per cell", { x: bx, y: 5.85, w: 2.7, h: 0.9, fontSize: 18, color: MUTED });
notes(s, "60s", "9:00-10:00", [
  ["20s", "Here we slowed IPv6 in 5 ms steps and kept IPv4 healthy. Top row: the share of runs IPv6 won. Every sweep cell was unanimous, 5 out of 5 one way or the other, so the outcome flips cleanly."],
  ["20s", "curl flips between 221 and 226 ms of IPv6 RTT; Chromium between 321 and 326. T is the time from the first SYN to the IPv4 SYN-ACK, read straight from the packets: 221.84 ms for curl and 321.99 for Chromium in this campaign. Each T sits inside its own flip bracket - two independent methods agree."],
  ["20s", "So IPv6 keeps winning as long as its RTT stays below about T: roughly 221 ms for curl and 321 ms for Chromium, in this lab. Bottom row: setup time climbs with the IPv6 RTT until the flip, then stays flat at T, because IPv4 is winning there. The diamonds are the jitter cells; they come on a later slide."],
], `T = ${n("curl_T_ls")} ms (curl) and ${n("chr_T_ls")} ms (Chromium), latency-sweep - always say the campaign.`);

// 10. Timeout sweep
s = pres.addSlide({ masterName: "CONTENT", sectionTitle: S });
title(s, "curl's timeout: T tracks timeout + IPv4 handshake");
img(s, "he", 0.4, 1.3, 5.45, 3300 / 1875, "curl T against configured --happy-eyeballs-timeout-ms, with residual panel, he-sweep S1");
const hx = 10.15;
text(s, "8 curl variants, 50 to 500 ms, IPv6 blackholed", { x: hx, y: 1.45, w: 2.85, h: 1.3, fontSize: 22, bold: true });
text(s, `T runs ${n("he_resid_all")} late in every variant`, { x: hx, y: 2.9, w: 2.85, h: 1.3, fontSize: 22 });
text(s, "A step between 250 and 300 ms that we cannot explain", { x: hx, y: 4.35, w: 2.85, h: 1.3, fontSize: 22 });
text(s, "he-sweep, n = 10 per cell", { x: hx, y: 6.0, w: 2.85, h: 0.5, fontSize: 18, color: MUTED });
notes(s, "40s", "10:00-10:40", [
  ["20s", "Plain curl doesn't let us see its timeout, so we set it: eight values from 50 to 500 ms, with IPv6 blackholed. The prediction was written down before the run: T should be the timeout plus the IPv4 handshake. It tracks that line across the whole range."],
  ["20s", "Say tracks, not equals: it runs 0.69 to 1.99 ms late in every variant, in two groups, with a step between 250 and 300 that we do not explain. The residual panel is shown as measured, uneven as it is. Control: curl with 200 set explicitly sent its IPv4 SYN at 200.833 ms, plain curl at 200.832."],
], `${n("he_resid_all")} late - 'tracks', never 'equals'.`);

// 11. Jitter
s = pres.addSlide({ masterName: "CONTENT", sectionTitle: S });
title(s, "With jitter, the winner becomes a probability");
const jrows = [
  [hdr("Client"), hdr("IPv6 jitter cell"), hdr("Model"), hdr("Observed, 95% Wilson")],
  ["curl", "±50 ms each way", n("j_curl50_pred").replace(/[| ]/g, ""), n("j_curl50_obs")],
  ["curl", "±70 ms each way", n("j_curl70_pred").replace(/[| ]/g, ""), n("j_curl70_obs")],
  ["Chromium", "±50 ms each way", n("j_chr50_pred").replace(/[| ]/g, ""), n("j_chr50_obs")],
  ["Chromium", "±70 ms each way", n("j_chr70_pred").replace(/[| ]/g, ""), n("j_chr70_obs")],
];
s.addTable(jrows, { x: 0.6, y: 1.4, w: 12.15, colW: [2.0, 3.3, 1.6, 5.25], rowH: 0.56, fontFace: FONT, fontSize: 22,
                    color: INK, border: { type: "solid", pt: 1, color: LINE }, valign: "middle", margin: [0, 0.12, 0, 0.12] });
tag(s, "Interpretation", 0.6, 4.45, 2.6);
text(s, "Model: P(IPv6 wins) = Φ((T − μ)/σ). All four cells match within their Wilson intervals.", { x: 3.45, y: 4.42, w: 9.3, h: 0.9, fontSize: 22 });
text(s, [
  { text: `Inputs measured independently of the outcomes: T from the no-jitter twins (${n("curl_T_jl")} / ${n("chr_T_jl")} ms, jitter-loss), μ and σ from the verify pings.`, options: { bullet: true, breakLine: true } },
  { text: "Written up together with the results, so not a pre-registered prediction. Its T values were fixed before the latency sweep, which then confirmed them.", options: { bullet: true } },
], { x: 0.6, y: 5.3, w: 12.15, h: 1.55, fontSize: 22, paraSpaceAfter: 6 });
notes(s, "40s", "10:40-11:20", [
  ["20s", "Add jitter to IPv6 and the outcome is no longer all or nothing: each run's IPv6 handshake time is random, and the winner depends on whether it beats T. We report win fractions with 95% Wilson intervals."],
  ["20s", "A simple normal model matches all four cells within their intervals. Its inputs were measured separately from the outcomes: T from the no-jitter twins, 221.96 and 322.47 ms in the jitter-loss campaign, and the spread from the verify pings. Be precise: the model was committed with its results, so do not call it a prediction made in advance. What was fixed in advance is T, and the later latency sweep confirmed it."],
], `T from the jitter-loss twins: ${n("curl_T_jl")} ms (curl), ${n("chr_T_jl")} ms (Chromium).`);

// 12. What the packets corrected
s = pres.addSlide({ masterName: "CONTENT", sectionTitle: S });
title(s, "What the packets corrected");
card(s, 0.6, 1.4, 4.6, 4.2);
text(s, "We predicted: it doubles", { x: 0.85, y: 1.55, w: 4.1, h: 0.45, bold: true, color: ACCENT });
text(s, `A doubling timer: SYNs at ${n("rto_pred_times")}, so gaps of about 1, 2 and 4 s.`, { x: 0.85, y: 2.1, w: 4.1, h: 1.6, fontSize: 22 });
text(s, "Committed to the findings doc on 21 Nov 2026 at 18:02 UTC, with results pending, before the campaign's first session.",
     { x: 0.85, y: 3.8, w: 4.1, h: 1.7, fontSize: 20, color: MUTED });
text(s, "The captures showed: gap to the next SYN on the same socket (Gv6c30)", { x: 5.4, y: 1.4, w: 7.35, h: 0.9, bold: true, fontSize: 22 });
const g = (k) => n(k).replace("median ", "");
const rto = [
  [hdr("Retransmission"), hdr("curl"), hdr("Chromium")],
  ["1st", g("rto_curl_1"), g("rto_chr_1")],
  ["2nd", g("rto_curl_2"), g("rto_chr_2")],
  ["3rd", g("rto_curl_3"), g("rto_chr_3")],
  ["4th", g("rto_curl_4"), "none"],
];
s.addTable(rto, { x: 5.4, y: 2.35, w: 7.35, colW: [2.35, 2.5, 2.5], rowH: 0.56, fontFace: FONT, fontSize: 20, color: INK,
                  border: { type: "solid", pt: 1, color: LINE }, valign: "middle", margin: [0, 0.12, 0, 0.12] });
text(s, "About 1 s every time, up to the fifth SYN.", { x: 5.4, y: 5.4, w: 7.35, h: 0.45, bold: true });
tag(s, "Interpretation", 0.6, 6.05, 2.6);
text(s, "matches net.ipv4.tcp_syn_linear_timeouts = 4 in hl-client", { x: 3.45, y: 6.05, w: 9.3, h: 0.5, fontSize: 22 });
notes(s, "40s", "11:20-12:00", [
  ["20s", "Our favourite result, because we got it wrong first. In the compound control - IPv4 blackholed and 30% loss on IPv6, so IPv6 is the only way through - the kernel's SYN retransmissions become visible. We predicted the textbook doubling timer: 1, 2, 4 seconds. Unlike the jitter model, that prediction is in the git history before the campaign ran."],
  ["20s", "The captures said otherwise: about one second between every SYN, up to the fifth, for both clients. Our reading, labelled as interpretation, is that this matches the kernel's tcp_syn_linear_timeouts setting, which is 4 in our client namespace. We corrected the findings doc and kept the wrong prediction visible."],
], "about 1 s between SYNs (1037.0 ms first gap for curl, then 1023.9 ms) - not 1, 2, 4 s.");

// 13. Prior work
s = pres.addSlide({ masterName: "CONTENT", sectionTitle: S });
title(s, "Prior work: we reproduce published delays");
const prow = [
  [hdr("Client"), hdr("Published CAD [1]"), hdr("Our inter-family delay, S1"), hdr("Our T (jitter-loss)")],
  ["curl", "200 ms", `${n("curl_ifd_S1")} ms`, `${n("curl_T_jl")} ms`],
  ["Chromium", "300 ms", `${n("chr_ifd_S1")} ms`, `${n("chr_T_jl")} ms`],
];
s.addTable(prow, { x: 0.6, y: 1.4, w: 12.15, colW: [2.2, 2.9, 4.2, 2.85], rowH: 0.56, fontFace: FONT, fontSize: 22, color: INK,
                   border: { type: "solid", pt: 1, color: LINE }, valign: "middle", margin: [0, 0.12, 0, 0.12] });
text(s, "They published these first: a reproduction, not a discovery.", { x: 0.6, y: 3.3, w: 12.15, h: 0.5, bold: true });
text(s, "What we add", { x: 0.6, y: 4.0, w: 12.15, h: 0.45, bold: true, color: ACCENT });
text(s, [
  { text: "the cost of racing against an oracle baseline, not measured in that work", options: { bullet: true, breakLine: true } },
  { text: "loss and jitter, with a win-fraction model; curl's timeout set to eight values", options: { bullet: true, breakLine: true } },
  { text: "a compound control that exposes the kernel's SYN timer", options: { bullet: true, breakLine: true } },
  { text: "certified datasets with hashes; uncertified data is refused", options: { bullet: true } },
], { x: 0.6, y: 4.5, w: 12.15, h: 1.85, fontSize: 22, paraSpaceAfter: 4 });
text(s, "[1] P. Sattler et al., “Lazy Eye Inspection: Capturing the State of Happy Eyeballs Implementations”, ACM IMC 2025 (arXiv 2412.00263).",
     { x: 0.6, y: 6.45, w: 12.15, h: 0.5, fontSize: 16, color: MUTED });
notes(s, "40s", "12:00-12:40", [
  ["20s", "Sattler and colleagues at TUM published curl's Connection Attempt Delay as 200 ms and Chromium-based browsers' as 300 ms. Our core data shows curl's IPv4 SYN 200.956 ms and Chromium's 301.067 ms after the first IPv6 SYN; T, which adds the IPv4 handshake, is 221.96 and 322.47 ms in jitter-loss. We reproduce their values independently; we did not discover them."],
  ["20s", "What we add is on the slide. If asked about internals: their paper says neither client implements the Resolution Delay - that is their claim, not ours; we only report packets. One refinement: they report one IPv6 and one IPv4 address tried; we see Chromium send a second IPv6 SYN to the same address from a new port, median 250.625 ms in S1, in 40 of 40 runs - one address, two attempts. Open question we cannot answer: whether the HEv3 behaviour they describe behind a Chromium flag is now on by default."],
], "reproduction, not discovery: 200 ms and 300 ms are theirs; 200.956 and 301.067 ms are ours.");

// 14. Limitations and what next
s = pres.addSlide({ masterName: "CONTENT", sectionTitle: S });
title(s, "Limitations, and what we would do next");
card(s, 0.6, 1.4, 6.0, 5.3);
card(s, 6.95, 1.4, 5.8, 5.3);
text(s, "What these data cannot show", { x: 0.85, y: 1.55, w: 5.5, h: 0.45, bold: true, color: ACCENT });
text(s, [
  { text: "one lab, one host, one kernel", options: { bullet: true, breakLine: true } },
  { text: "synthetic netem impairments, not carrier measurements", options: { bullet: true, breakLine: true } },
  { text: "plain HTTP: no TLS, QUIC or SVCB", options: { bullet: true, breakLine: true } },
  { text: "two clients, one version each", options: { bullet: true, breakLine: true } },
  { text: "one AAAA and one A: not how many addresses a client would try", options: { bullet: true } },
], { x: 0.85, y: 2.1, w: 5.5, h: 4.5, fontSize: 22, paraSpaceAfter: 8 });
text(s, "With more time", { x: 7.2, y: 1.55, w: 5.3, h: 0.45, bold: true, color: ACCENT });
text(s, [
  { text: "repeat on a second host and kernel", options: { bullet: true, breakLine: true } },
  { text: "several AAAA and A records per name", options: { bullet: true, breakLine: true } },
  { text: "delay the A answer, the counterpart of S6", options: { bullet: true, breakLine: true } },
  { text: "TLS, QUIC and HTTPS/SVCB records", options: { bullet: true, breakLine: true } },
  { text: "more clients and versions; share the data with the IETF HAPPY working group", options: { bullet: true } },
], { x: 7.2, y: 2.1, w: 5.3, h: 4.5, fontSize: 22, paraSpaceAfter: 8 });
notes(s, "40s", "12:40-13:20", [
  ["20s", "Limits, plainly: one lab on one host and kernel, synthetic impairments - mobile-inspired latency conditions, not carrier measurements - plain HTTP only, two clients at one version each. And our DNS returns one IPv6 and one IPv4 address, so we cannot say how many addresses a client would try."],
  ["20s", "Next: a second host and kernel; names with several addresses; delaying the A answer instead of AAAA, which would address the open S6 question; TLS, QUIC and SVCB; more clients. Everything is in the repository - code, report and the certified datasets. Thank you."],
], "1,328 runs, all from one host - say it as a limit, not just a boast.");

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
