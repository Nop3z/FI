"""Regenerate dev/preview.html from the bundled frontend assets.

Usage:
    python scripts/build_preview.py

The package itself needs no build step; this dev page is a standalone visual
acceptance harness for browsers without Jupyter and is intentionally generated
so it never drifts from src/viewviewview/static/{index.mjs,styles.css}.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INDEX_JS = (ROOT / "src" / "viewviewview" / "static" / "index.mjs").read_text(encoding="utf-8")
CSS = (ROOT / "src" / "viewviewview" / "static" / "styles.css").read_text(encoding="utf-8")

DEMO = r"""
/* ---- preview-only bootstrap (not part of index.mjs) ---- */

// Mock payload: state / delay / pulse / reply / errcode, 34 rows, newest first.
// counts are full-history totals (890/40/12 -> total 942); rows only the window.
const initialPayload = {
  columns: [
    { name: "state", type: "str" },
    { name: "delay", type: "int" },
    { name: "pulse", type: "float" },
    { name: "reply", type: "str" },
    { name: "errcode", type: "int" },
  ],
  state_key: "state",
  counts: { PASS: 890, FAIL: 40, TIMEOUT: 12 },
  rows: [
    ["PASS", 176, 12.5, "ok", 0],
    ["FAIL", 191, 13.1, "no-reply", 3],
    ["PASS", 164, 12.0, "ok", 0],
    ["TIMEOUT", 159, 11.8, "open", 7],
    ["PASS", 182, 12.7, "ok", 0],
    ["PASS", 171, 12.2, null, 0],
    ["FAIL", 168, 12.4, "short", 2],
    ["PASS", 177, 12.6, "ok", 0],
    ["PASS", 163, 11.9, "ok", 0],
    ["TIMEOUT", 155, 11.6, "open", 7],
    ["PASS", 189, 13.0, "ok", 0],
    ["PASS", 172, 12.3, "ok", 0],
    ["PASS", 166, 12.1, "ok", 0],
    ["FAIL", 184, 12.9, "no-reply", 1],
    ["PASS", 158, 11.7, "ok", 0],
    ["PASS", 175, 12.5, "ok", 0],
    ["PASS", 169, 12.2, "ok", 0],
    ["TIMEOUT", 161, 11.9, "open", 7],
    ["PASS", 188, 12.9, "ok", 0],
    ["PASS", 174, 12.4, "ok", 0],
    ["PASS", 167, 12.1, "ok", 0],
    ["FAIL", 193, 13.2, "short", 4],
    ["PASS", 173, 12.4, "ok", 0],
    ["PASS", 162, 11.8, "ok", 0],
    ["PASS", 179, 12.7, "ok", 0],
    ["PASS", 170, 12.3, "ok", 0],
    ["TIMEOUT", 160, 11.8, "open", 7],
    ["PASS", 186, 12.8, "ok", 0],
    ["PASS", 165, 12.0, "ok", 0],
    ["PASS", 178, 12.6, "ok", 0],
    ["FAIL", 192, 13.1, "no-reply", 3],
    ["PASS", 160, 11.8, "ok", 0],
    ["PASS", 173, 12.3, "ok", 0],
    ["PASS", 185, 12.7, "ok", 0],
  ],
  total: 942,
  window: 34,
  version: 1042,
};

// Shadow DOM boot: mirrors how anywidget mounts a widget that ships _css.
const host = document.getElementById("vvv-preview");
const shadow = host.attachShadow({ mode: "open" });
const styleElement = document.createElement("style");
styleElement.textContent = document.getElementById("vvv-css-src").textContent;
shadow.appendChild(styleElement);
const el = document.createElement("div");
el.style.height = "100%";
shadow.appendChild(el);

// Minimal mock model: get/on/off semantics aligned with ipywidgets.
let currentPayload = initialPayload;
const payloadListeners = [];
const mockModel = {
  get: (key) =>
    key === "payload" ? currentPayload : key === "theme" ? "dark" : undefined,
  on: (event, callback) => {
    if (event === "change:payload") {
      payloadListeners.push(callback);
    }
  },
  off: (event, callback) => {
    if (event === "change:payload") {
      const index = payloadListeners.indexOf(callback);
      if (index !== -1) {
        payloadListeners.splice(index, 1);
      }
    }
  },
};

render({ model: mockModel, el });

// Simulate the Syncer's coalesced snapshots: total/counts/version grow, a new
// row is unshifted, window depth stays at 34 (ring buffer).
let demoRowSeed = 942;
document.getElementById("vvv-push").addEventListener("click", () => {
  demoRowSeed += 1;
  currentPayload = {
    ...currentPayload,
    counts: {
      ...currentPayload.counts,
      PASS: currentPayload.counts.PASS + 1,
    },
    rows: [
      ["PASS", 150 + (demoRowSeed % 50), +(11.5 + (demoRowSeed % 20) / 10).toFixed(1), "ok", 0],
      ...currentPayload.rows.slice(0, 33),
    ],
    total: demoRowSeed,
    version: currentPayload.version + 7,
  };
  payloadListeners.forEach((listener) => listener());
});

// ?resize -> synthesize one column drag so screenshots can prove the feature.
if (new URLSearchParams(location.search).has("resize")) {
  requestAnimationFrame(() => {
    const table = shadow.querySelector("table.vvv-table--detail");
    if (!table) return;
    const handles = table.querySelectorAll(".vvv-resize");
    const handle = handles[handles.length - 1];
    if (!handle) return;
    const rect = handle.getBoundingClientRect();
    const startX = rect.left + rect.width / 2;
    const pointer = { bubbles: true, button: 0, pointerId: 7 };
    handle.dispatchEvent(new PointerEvent("pointerdown", { ...pointer, clientX: startX }));
    handle.dispatchEvent(new PointerEvent("pointermove", { ...pointer, clientX: startX + 160 }));
    handle.dispatchEvent(new PointerEvent("pointerup", { ...pointer, clientX: startX + 160 }));
  });
}
"""

TEMPLATE = """<!doctype html>
<!--
  GENERATED by scripts/build_preview.py — do not edit by hand.
  Standalone dual-pane visual acceptance page (no Jupyter / no build step).
-->
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ViewViewView · dev preview</title>
<style>
  /* Page-level demo shell only; component styles live in the shadow root. */
  body {
    background: #14181d;
    color: #e6ebf1;
    font-family: system-ui, "Segoe UI", "Microsoft YaHei", sans-serif;
    margin: 0;
    padding: 24px 32px 40px;
  }
  h1 { font-size: 18px; margin: 0 0 4px; }
  p.meta { color: #8b95a1; font-size: 12px; margin: 0 0 12px; }
  button {
    background: #2b323a;
    border: 1px solid #333b45;
    border-radius: 6px;
    color: #dfe3e8;
    cursor: pointer;
    font-size: 12px;
    margin: 0 8px 12px 0;
    padding: 6px 14px;
  }
  button:hover { background: #3d6fe0; border-color: #3d6fe0; color: #ffffff; }
  #vvv-preview { height: 640px; }
</style>
</head>
<body>
  <h1>ViewViewView · preview.html</h1>
  <p class="meta">
    模拟载荷 state / delay / pulse / reply / errcode · total 942 · window 34 ·
    counts: PASS 890 / FAIL 40 / TIMEOUT 12 · 拖动表头分隔线可调整列宽
  </p>
  <button id="vvv-push" type="button">模拟一次推送（change:payload）</button>
  <div id="vvv-preview"></div>

  <script type="text/plain" id="vvv-css-src">__CSS__</script>
  <script type="module">
__INDEX_JS__

__DEMO__
  </script>
</body>
</html>
"""


def main() -> None:
    html = (
        TEMPLATE.replace("__CSS__", CSS)
        .replace("__INDEX_JS__", INDEX_JS)
        .replace("__DEMO__", DEMO)
    )
    output = ROOT / "dev" / "preview.html"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html, encoding="utf-8", newline="\n")
    print(f"wrote {output} ({len(html)} chars)")


if __name__ == "__main__":
    main()
