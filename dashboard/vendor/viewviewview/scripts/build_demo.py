"""Build the real-core visual demo used for acceptance screenshots.

Runs an actual ``ViewWidget`` injection campaign (declared columns, CSV
recording, counts, ring window), captures the payload the frontend receives,
and writes a standalone demo page + a gallery shell under ``dev/``.

Usage:
    python scripts/build_demo.py
    python scripts/build_demo.py --rows 5000
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import viewviewview  # noqa: E402
import viewviewview.core as core  # noqa: E402

COLUMNS = {
    "state": str,
    "delay": int,
    "pulse": int,
    "reply": str,
    "errcode": int,
}


def capture_show_payload(widget):
    """Capture exactly what ``show()`` sends to the panel frontend."""
    captured = {}
    original = core.render_payload

    def fake_render(payload, colors=None, number_columns=None, on_created=None):
        captured["payload"] = payload

    core.render_payload = fake_render
    try:
        widget.show()
    finally:
        core.render_payload = original
    return captured["payload"]


def simulate_injections(rows: int, seed: int = 20261019):
    rng = random.Random(seed)
    stats = {}
    with tempfile.TemporaryDirectory(prefix="vvv-demo-") as directory:
        path = Path(directory) / "demo.csv"
        widget = viewviewview.ViewWidget(
            csv_path=path,
            columns=COLUMNS,
            live_rows=1000,
            flush_every=100,
        )
        started = time.perf_counter()
        for index in range(rows):
            roll = rng.random()
            if index >= rows - 12:
                # Make the newest window visually representative of all classes.
                state = ("PASS", "FAIL", "TIMEOUT")[index % 3]
                if state == "PASS":
                    reply, errcode = "ok", 0
                elif state == "FAIL":
                    reply, errcode = rng.choice(["no-reply", "short"]), rng.randint(1, 8)
                else:
                    reply, errcode = "open", 7
            elif roll < 0.018:
                state, reply, errcode = "TIMEOUT", "open", 7
            elif roll < 0.10:
                state, reply, errcode = "FAIL", rng.choice(["no-reply", "short"]), rng.randint(1, 8)
            else:
                state, reply, errcode = "PASS", "ok", 0
            widget.update(
                state=state,
                delay=rng.randint(100, 2000),
                pulse=rng.randint(10, 50),
                reply=reply,
                errcode=errcode,
            )
        elapsed = time.perf_counter() - started
        payload = capture_show_payload(widget)
        stats = {
            "rows": rows,
            "elapsed_s": round(elapsed, 3),
            "csv_bytes": path.stat().st_size,
            "csv_rows": widget.rows_written,
            "counts": payload["counts"],
            "payload_rows": payload["window"],
            "total": payload["total"],
        }
        widget.close()
    return payload, stats


def empty_payload():
    widget = viewviewview.ViewWidget(columns=COLUMNS)
    payload = capture_show_payload(widget)
    widget.close()
    return payload


INDEX_JS = (ROOT / "src" / "viewviewview" / "static" / "index.mjs").read_text(encoding="utf-8")
CSS = (ROOT / "src" / "viewviewview" / "static" / "styles.css").read_text(encoding="utf-8")

DEMO_JS = r"""
/* ---- demo bootstrap (not part of index.mjs) ---- */

const PAYLOADS = __PAYLOADS__;
const params = new URLSearchParams(location.search);
const startName = params.get("demo") === "empty" ? "empty" : "live";
let currentName = startName;
let currentPayload = PAYLOADS[startName];
const listeners = [];

const model = {
  get: (key) =>
    key === "payload" ? currentPayload : key === "theme" ? "dark" : undefined,
  on: (event, callback) => {
    if (event === "change:payload") listeners.push(callback);
  },
  off: (event, callback) => {
    const index = listeners.indexOf(callback);
    if (index !== -1) listeners.splice(index, 1);
  },
};

const host = document.getElementById("vvv-preview");
const shadow = host.attachShadow({ mode: "open" });
const styleElement = document.createElement("style");
styleElement.textContent = document.getElementById("vvv-css-src").textContent;
shadow.appendChild(styleElement);
const el = document.createElement("div");
el.style.height = "100%";
shadow.appendChild(el);

render({ model, el });

function refresh(name) {
  currentName = name;
  currentPayload = PAYLOADS[name];
  listeners.forEach((listener) => listener());
  document.getElementById("vvv-mode").textContent =
    name === "empty" ? "空表骨架（尚未注入）" : `真实运行结果（${PAYLOADS.live.total} 次注入）`;
}
refresh(startName);

document.getElementById("vvv-empty").addEventListener("click", () => refresh("empty"));
document.getElementById("vvv-live").addEventListener("click", () => refresh("live"));

// Simulate one coalesced Syncer frame on the live payload.
let pushed = 0;
document.getElementById("vvv-push").addEventListener("click", () => {
  if (currentName !== "live") return;
  pushed += 1;
  const base = PAYLOADS.live;
  const nextRow = ["PASS", 170 + (pushed % 30), 12 + (pushed % 7), "ok", 0];
  currentPayload = {
    ...base,
    counts: { ...base.counts, PASS: base.counts.PASS + pushed },
    rows: [nextRow, ...base.rows.slice(0, base.rows.length - 1)],
    total: base.total + pushed,
    version: base.version + pushed * 7,
  };
  listeners.forEach((listener) => listener());
});

// ?resize -> synthesize one column drag (state | delay divider) for screenshots.
if (params.has("resize")) {
  requestAnimationFrame(() => {
    const table = shadow.querySelector("table.vvv-table--detail");
    if (!table) return;
    const handles = table.querySelectorAll(".vvv-resize");
    const handle = handles[handles.length - 1];
    if (!handle) return;
    const rect = handle.getBoundingClientRect();
    const startX = rect.left + rect.width / 2;
    const pointer = { bubbles: true, button: 0, pointerId: 11 };
    handle.dispatchEvent(new PointerEvent("pointerdown", { ...pointer, clientX: startX }));
    handle.dispatchEvent(new PointerEvent("pointermove", { ...pointer, clientX: startX + 160 }));
    handle.dispatchEvent(new PointerEvent("pointerup", { ...pointer, clientX: startX + 160 }));
  });
}
"""

DEMO_HTML = """<!doctype html>
<!-- GENERATED by scripts/build_demo.py (real payloads captured from ViewWidget). -->
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ViewViewView · 实测效果</title>
<style>
  body { background:#14181d; color:#e6ebf1; font-family:system-ui,"Segoe UI","Microsoft YaHei",sans-serif; margin:0; padding:20px 28px 32px; }
  h1 { font-size:18px; margin:0 0 4px; }
  p.meta { color:#8b95a1; font-size:12px; margin:0 0 10px; }
  #vvv-mode { color:#8b95a1; font-size:12px; margin-left:8px; }
  button { background:#2b323a; border:1px solid #333b45; border-radius:6px; color:#dfe3e8; cursor:pointer; font-size:12px; margin:0 8px 10px 0; padding:6px 14px; }
  button:hover { background:#3d6fe0; border-color:#3d6fe0; color:#fff; }
  #vvv-preview { height:620px; }
</style>
</head>
<body>
  <h1>ViewViewView · 实测效果 <span id="vvv-mode"></span></h1>
  <p class="meta">
    数据来自真实 Python 核心：columns 预声明、CSV 落盘、分类计数与环形窗口 · 拖动表头分隔线可调整列宽
  </p>
  <div>
    <button id="vvv-empty" type="button">空表骨架</button>
    <button id="vvv-live" type="button">真实运行结果</button>
    <button id="vvv-push" type="button">模拟一次推送</button>
  </div>
  <div id="vvv-preview"></div>
  <script type="text/plain" id="vvv-css-src">__CSS__</script>
  <script type="module">
__INDEX_JS__

__DEMO_JS__
  </script>
</body>
</html>
"""

GALLERY_HTML = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>ViewViewView · 效果图</title>
<style>
  body { background:#0e1216; color:#e6ebf1; font-family:system-ui,"Segoe UI","Microsoft YaHei",sans-serif; margin:0; padding:22px 28px 34px; }
  h1 { font-size:19px; margin:0 0 6px; }
  p.lead { color:#9aa4b2; font-size:12px; margin:0 0 18px; }
  .shot { margin:0 0 20px; }
  .shot img { width:1000px; display:block; border:1px solid #333b45; border-radius:8px; }
  .cap { color:#9aa4b2; font-size:12px; margin:6px 0 0; }
</style>
</head>
<body>
  <h1>ViewViewView · 实测效果</h1>
  <p class="lead">真实 Python 核心产出的载荷（__ROWS__ 次模拟注入），经 bundled 前端渲染；列宽图为合成拖拽后的效果。</p>
  <div class="shot"><img src="demo-empty.png" alt="empty"><p class="cap">① 实例化 columns=... 后 vt.show()：5 列空表骨架，尚未注入</p></div>
  <div class="shot"><img src="demo-live.png" alt="live"><p class="cap">② 真实运行结果：上窗分类计数（绿色 #19ff25）、下窗最新 1000 行明细（live_rows 窗口）、底部总数与 live 状态</p></div>
  <div class="shot"><img src="demo-resize.png" alt="resize"><p class="cap">③ 拖动表头分隔线：state 列收窄、delay 列加宽（宽度在实时刷新间保持）</p></div>
</body>
</html>
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows", type=int, default=5000)
    args = parser.parse_args()

    live, stats = simulate_injections(args.rows)
    empty = empty_payload()
    payloads = {"empty": empty, "live": live}

    dev = ROOT / "dev"
    dev.mkdir(parents=True, exist_ok=True)

    demo_js = DEMO_JS.replace("__PAYLOADS__", json.dumps(payloads, ensure_ascii=False))
    demo = (
        DEMO_HTML.replace("__CSS__", CSS)
        .replace("__INDEX_JS__", INDEX_JS)
        .replace("__DEMO_JS__", demo_js)
    )
    (dev / "demo.html").write_text(demo, encoding="utf-8", newline="\n")
    (dev / "demo-gallery.html").write_text(
        GALLERY_HTML.replace("__ROWS__", f"{stats['rows']:,}"),
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps(stats, ensure_ascii=False))
    print(f"wrote {dev / 'demo.html'}")
    print(f"wrote {dev / 'demo-gallery.html'}")


if __name__ == "__main__":
    main()
