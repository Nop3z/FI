"""Front-end memory regression harness (docs/VERIFICATION.md baseline).

Drives the real ``index.mjs`` renderer inside a headless browser and asserts
the three S1 acceptance criteria (incremental rendering, see
``docs/ARCHITECTURE.md`` change log):

1. shadow-DOM node count stays constant across the whole run (no per-frame
   rebuild churn, no leak);
2. mean per-frame render time stays under ``MAX_FRAME_MS``;
3. after a forced GC the used JS heap returns to within ``MAX_HEAP_DRIFT_MB``
   of the baseline sample (no unbounded growth).
4. (stats on) the optional delay-statistics charts exist, keep a constant
   node pool and their timeline bars equal the final payload snapshot.
   Stats ride on every second build (interval-gate emulation).
   Mode ``2`` additionally enables ``stats_custom=`` (third chart in the
   right column with a 6th bucket counter).

Usage::

    python scripts/mem_baseline.py [frames] [interval_ms] [depth] [columns] [stats]

Defaults: 3000 frames, 50 ms interval (Syncer pace), depth 1000, 5 columns,
stats pane mode 1 (enabled; 0 = off, 2 = on + stats_custom "FAIL").
Requires ``playwright`` with a chromium-family browser installed.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INDEX_JS = (ROOT / "src" / "viewviewview" / "static" / "index.mjs").read_text(encoding="utf-8")
CSS = (ROOT / "src" / "viewviewview" / "static" / "styles.css").read_text(encoding="utf-8")

MAX_FRAME_MS = 13.0
MAX_HEAP_DRIFT_MB = 5.0
MAX_NODE_DRIFT = 5

COLUMNS = [
    {"name": "state", "type": "str"},
    {"name": "delay", "type": "int"},
    {"name": "pulse", "type": "float"},
    {"name": "reply", "type": "str"},
    {"name": "errcode", "type": "int"},
]

PAGE = """<!doctype html>
<html>
<head><meta charset="utf-8"><style>html,body{{margin:0;padding:8px;}}</style></head>
<body>
<div id="host" style="height:480px;"></div>
<script>
window.__css = {css!r};
window.__columns = {columns!r};
window.__depth = {depth};
</script>
<script type="module">
{js}
// harness bridge: expose the anywidget default export for the driver below
window.__vvvRender = {{ render }};
</script>
</body>
</html>
"""


def build_page(depth: int, columns: list) -> str:
    js = INDEX_JS + "\nwindow.__vvvRender = { render };\n"
    return PAGE.format(js=js, css=CSS, columns=columns, depth=depth)





def main() -> int:
    frames = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
    interval_ms = int(sys.argv[2]) if len(sys.argv) > 2 else 50
    depth = int(sys.argv[3]) if len(sys.argv) > 3 else 1000
    columns = COLUMNS[: int(sys.argv[4])] if len(sys.argv) > 4 else COLUMNS
    stats_mode = int(sys.argv[5]) if len(sys.argv) > 5 else 1

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("playwright is required: pip install playwright && playwright install chromium")
        return 2

    html_path = ROOT / "dev" / "mem_harness.html"
    html_path.write_text(build_page(depth, columns), encoding="utf-8")

    with sync_playwright() as pw:
        try:
            browser = pw.chromium.launch(
                channel="msedge",
                headless=True,
                args=["--js-flags=--expose-gc", "--enable-precise-memory-info"],
            )
        except Exception:
            browser = pw.chromium.launch(
                args=["--js-flags=--expose-gc", "--enable-precise-memory-info"]
            )
        page = browser.new_page()
        page.goto(html_path.as_uri())

        # The module script exports { render }; grab it via an addEventListener
        # bridge the page sets up (see driver).
        page.evaluate(
            """
            ([frames, interval]) => {
              window.__args = [frames, interval];
              return true;
            }
            """,
            [frames, interval_ms],
        )

        result = page.evaluate(
            """
            async ([frames, interval, depth, statsMode]) => {
              // 0 = pane off, 1 = pane on, 2 = pane on + stats_custom "FAIL".
              const extraMode = statsMode === 2;
              const render = window.__vvvRender.render;

              const host = document.getElementById("host");
              const shadow = host.attachShadow({ mode: "open" });
              const style = document.createElement("style");
              style.textContent = window.__css;
              shadow.appendChild(style);
              const el = document.createElement("div");
              el.style.height = "100%";
              shadow.appendChild(el);

              const columns = window.__columns;
              let payload = null;
              const listeners = [];
              const model = {
                get: (key) => (key === "payload" ? payload : key === "theme" ? "dark" : undefined),
                on: (event, cb) => { if (event === "change:payload") listeners.push(cb); },
                off: (event, cb) => {
                  const i = listeners.indexOf(cb);
                  if (i !== -1) listeners.splice(i, 1);
                },
              };

              const seedRow = (n) => [
                ["PASS", "FAIL", "TIMEOUT", "HANG"][n % 4],
                100 + (n % 3900),
                10 + (n % 40) + 0.5,
                ["ok", "short", "open"][n % 3],
                n % 9,
              ];

              // CSV-rooted statistics mirror: every accepted row 1..n folds
              // into one bucket slot — [total, ok, hang] (+ custom in mode 2,
              // where FAIL is charted as the user-defined third state) —
              // exactly what the core does per accepted record.
              const bucketAgg = new Map();
              let statsRows = 0;
              const ingestStat = (n) => {
                const row = seedRow(n);
                const lo = Math.floor(row[1] / 100) * 100;
                let slot = bucketAgg.get(lo);
                if (!slot) {
                  slot = extraMode ? [0, 0, 0, 0] : [0, 0, 0];
                  bucketAgg.set(lo, slot);
                }
                slot[0] += 1;
                if (row[0] === "PASS") slot[1] += 1;
                if (row[0] === "HANG") slot[2] += 1;
                if (extraMode && row[0] === "FAIL") slot[3] += 1;
                statsRows = n;
              };
              const makeStats = () => ({
                bucket: 100,
                bars: 30,
                success: "PASS",
                hang: "HANG",
                ...(extraMode ? { custom: "FAIL" } : {}),
                rows: statsRows,
                buckets: Array.from(bucketAgg)
                  .sort((a, b) => a[0] - b[0])
                  .map(([lo, slot]) =>
                    extraMode
                      ? [lo, lo + 100, slot[0], slot[1], slot[2], slot[3]]
                      : [lo, lo + 100, slot[0], slot[1], slot[2]],
                  ),
              });

              const makePayload = (n, withStats) => {
                for (let r = statsRows + 1; r <= n; r += 1) ingestStat(r);
                const rows = [];
                for (let i = 0; i < Math.min(depth, n); i += 1) rows.push(seedRow(n - i));
                const payload = {
                  columns,
                  state_key: "state",
                  counts: {
                    PASS: Math.floor(n / 3) + 1,
                    FAIL: Math.floor(n / 3),
                    TIMEOUT: Math.floor(n / 3),
                  },
                  rows,
                  total: n,
                  window: rows.length,
                  version: n,
                };
                // Interval-gate emulation: stats ride on every second build,
                // and always on the first build and the final build.
                if (withStats) payload.stats = makeStats();
                return payload;
              };

              const countNodes = () => {
                let total = 0;
                const walk = (node) => {
                  total += 1;
                  if (node.shadowRoot) walk(node.shadowRoot);
                  for (const child of node.children || []) walk(child);
                };
                for (const child of shadow.children) walk(child);
                return total;
              };
              const heapUsed = () =>
                performance.memory ? performance.memory.usedJSHeapSize : 0;

              // ---- initial render ----
              payload = makePayload(depth, statsMode);
              const teardown = render({ model, el });

              gc(); gc(); gc();
              const baseNodes = countNodes();
              const baseHeap = heapUsed();

              const frameTimes = [];
              let nodesMin = baseNodes;
              let nodesMax = baseNodes;
              const t0 = performance.now();

              const finalN = depth + frames;
              for (let n = depth + 1; n <= finalN; n += 1) {
                const withStats = statsMode
                  ? (n - depth) % 2 === 0 || n === finalN
                  : false;
                const next = makePayload(n, withStats);
                const tFrame = performance.now();
                payload = next;
                listeners.forEach((cb) => cb());
                frameTimes.push(performance.now() - tFrame);
                const nodes = countNodes();
                if (nodes < nodesMin) nodesMin = nodes;
                if (nodes > nodesMax) nodesMax = nodes;
                await new Promise((r) => setTimeout(r, interval));
              }

              gc(); gc(); gc();
              const endHeap = heapUsed();

              // Correctness: the patched DOM must equal the last payload.
              const body = shadow.querySelector("table.vvv-table--detail tbody");
              let domMismatches = 0;
              const samples = [];
              for (let i = 0; i < payload.rows.length; i += 1) {
                const tr = body.children[i];
                for (let j = 0; j < columns.length; j += 1) {
                  const raw = payload.rows[i][j];
                  const want = raw === null || raw === undefined ? "" : String(raw);
                  const got = tr && tr.children[j] ? tr.children[j].textContent : null;
                  if (got !== want) {
                    domMismatches += 1;
                    if (samples.length < 5) samples.push([i, j, got, want]);
                  }
                }
              }

              // Correctness: the optional stats charts must equal the final
              // snapshot along the delay timeline (bucket start ascending,
              // oldest end dropped beyond ``bars``); bars grow upward with a
              // px height and exact numbers ride in the data-tip hover tag.
              let statsMismatches = 0;
              const statsSamples = [];
              const finalStats = statsMode ? payload.stats || null : null;
              if (statsMode && finalStats === null) {
                statsMismatches += 1;
                statsSamples.push(["final stats missing"]);
              }
              const pane = shadow.querySelector(".vvv-pane--stats");
              if (statsMode && pane === null) {
                statsMismatches += 1;
                statsSamples.push(["stats pane missing"]);
              } else if (!statsMode && pane !== null) {
                statsMismatches += 1;
                statsSamples.push(["unexpected stats pane"]);
              }
              if (statsMode && finalStats !== null && pane !== null) {
                const charts = pane.querySelectorAll(".vvv-stat-chart");
                const wantCharts = extraMode ? 3 : 2;
                if (charts.length !== wantCharts) {
                  statsMismatches += 1;
                  statsSamples.push(["chart plots", charts.length]);
                }
                const maxBars = finalStats.bars;
                for (let chart = 0; chart < charts.length; chart += 1) {
                  // chart order: 成功分布, HANG分布, then the optional custom
                  // one. metric index into [lo, hi, total, ok, hang, custom];
                  // bar heights are normalized to the chart's tallest bucket
                  // (matching the frontend) while the hover tag keeps the
                  // true share of the metric's cumulative total.
                  const metric = chart === 0 ? 3 : chart === 1 ? 4 : 5;
                  const metricLabel =
                    chart === 0 ? "成功" : chart === 1 ? "HANG" : "FAIL";
                  const entries = [];
                  let totalHits = 0;
                  for (const b of finalStats.buckets) {
                    if (
                      b[2] > 0 &&
                      typeof b[metric] === "number" &&
                      b[metric] >= 0
                    ) {
                      entries.push([
                        b[0],
                        b[1],
                        b[2],
                        b[metric],
                        0,
                        0,
                      ]);
                      totalHits += b[metric];
                    }
                  }
                  entries.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
                  let maxHits = 0;
                  for (const e of entries) {
                    if (e[3] > maxHits) maxHits = e[3];
                  }
                  for (const e of entries) {
                    e[4] = maxHits > 0 ? Math.min(e[3] / maxHits, 1) : 0;
                    e[5] = totalHits > 0 ? Math.min(e[3] / totalHits, 1) : 0;
                  }
                  const visible = entries.slice(
                    Math.max(0, entries.length - maxBars),
                  );
                  // 成功分布/HANG分布 use the shared 122px plot; the custom
                  // chart stretches across a doubled 244px plot area.
                  const plotPx = chart === 2 ? 244 : 122;
                  const cols = Array.from(charts[chart].children).filter(
                    (node) =>
                      node.classList && node.classList.contains("vvv-stat-col"),
                  );
                  let shown = 0;
                  cols.forEach((col, index) => {
                    const want = index < visible.length ? visible[index] : null;
                    if (col.style.display === "none") {
                      if (want !== null) {
                        statsMismatches += 1;
                        statsSamples.push([chart, index, "hidden", want[0]]);
                      }
                      return;
                    }
                    shown += 1;
                    if (want === null) {
                      statsMismatches += 1;
                      statsSamples.push([chart, index, "unexpected visible"]);
                      return;
                    }
                    const label = `${want[0]}-${want[1]}`;
                    const cite = `${label} · ${metricLabel} ${want[3]}/${totalHits} · ${(
                      want[5] * 100
                    ).toFixed(1)}%`;
                    const wantHeight = Math.max(Math.round(want[4] * plotPx), 0);
                    const labelText = col.children[1].textContent;
                    if (labelText !== label) {
                      statsMismatches += 1;
                      statsSamples.push([chart, index, "label", labelText, label]);
                    }
                    if (col.dataset.tip !== cite) {
                      statsMismatches += 1;
                      statsSamples.push([chart, index, "tip", col.dataset.tip, cite]);
                    }
                    const gotHeight = parseFloat(col.children[0].style.height);
                    if (!(Math.abs(gotHeight - wantHeight) <= 0.006)) {
                      statsMismatches += 1;
                      statsSamples.push([
                        chart,
                        index,
                        "height",
                        col.children[0].style.height,
                        `${wantHeight}px`,
                      ]);
                    }
                  });
                  if (shown !== visible.length) {
                    statsMismatches += 1;
                    statsSamples.push([chart, "shown", shown, visible.length]);
                  }
                }
              }
              return {
                frames,
                baseNodes,
                nodesMin,
                nodesMax,
                meanFrameMs: frameTimes.reduce((a, b) => a + b, 0) / frameTimes.length,
                p95FrameMs: frameTimes.slice().sort((a, b) => a - b)[
                  Math.floor(frameTimes.length * 0.95)
                ],
                baseHeapMB: baseHeap / 1048576,
                endHeapMB: endHeap / 1048576,
                heapDriftMB: (endHeap - baseHeap) / 1048576,
                wallSeconds: (performance.now() - t0) / 1000,
                domMismatches,
                domSamples: samples,
                statsMismatches,
                statsSamples: statsSamples.slice(0, 5),
              };
            }
            """,
            [frames, interval_ms, depth, stats_mode],
        )

        browser.close()

    mean = result["meanFrameMs"]
    p95 = result["p95FrameMs"]
    drift = result["heapDriftMB"]
    node_drift = result["nodesMax"] - result["nodesMin"]

    print(
        f"frames={result['frames']} depth={depth} cols={len(columns)} "
        f"stats={['off', 'on', 'on+custom'][stats_mode] if 0 <= stats_mode < 3 else stats_mode}"
    )
    print(
        "shadow nodes: "
        f"base={result['baseNodes']} min={result['nodesMin']} "
        f"max={result['nodesMax']} (drift {node_drift})"
    )
    print(f"frame time: mean={mean:.2f}ms p95={p95:.2f}ms (budget {MAX_FRAME_MS}ms)")
    print(
        f"heap: base={result['baseHeapMB']:.1f}MB end={result['endHeapMB']:.1f}MB "
        f"drift={drift:+.1f}MB (budget {MAX_HEAP_DRIFT_MB}MB)"
    )
    print(f"dom mismatches: {result['domMismatches']}")
    print(f"stats pane mismatches: {result['statsMismatches']}")

    failures = []
    if mean >= MAX_FRAME_MS:
        failures.append(f"mean frame time {mean:.2f}ms >= {MAX_FRAME_MS}ms")
    if drift >= MAX_HEAP_DRIFT_MB:
        failures.append(f"forced-GC heap drift {drift:.1f}MB >= {MAX_HEAP_DRIFT_MB}MB")
    if node_drift > MAX_NODE_DRIFT:
        failures.append(f"node count drift {node_drift} > {MAX_NODE_DRIFT}")
    if result["domMismatches"]:
        failures.append(
            f"DOM does not match payload: {result['domMismatches']} cells, "
            f"samples={result['domSamples']}"
        )
    if result["statsMismatches"]:
        failures.append(
            f"stats pane does not match payload: {result['statsMismatches']} bars, "
            f"samples={result['statsSamples']}"
        )

    if failures:
        print("FAIL: " + "; ".join(failures))
        return 1
    print("PASS: memory baseline holds (constant DOM, bounded heap)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
