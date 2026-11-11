"""Capture a real JupyterLab screenshot after running the demo notebook.

Requires the local JupyterLab server and Microsoft Edge (Playwright uses the
installed Edge channel; no browser download needed).

Usage:
    python scripts/capture_jupyter.py [notebook_url] [output_png]
"""

from __future__ import annotations

import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

DEFAULT_URL = (
    "http://127.0.0.1:8899/lab/tree/dev/jupyter_demo.ipynb?token=vvv-demo"
)
DEFAULT_OUT = "dev/jupyter-live.png"


def scroll_widget_into_view(page) -> None:
    """Scroll the notebook so the ViewViewView top pane sits mid-viewport."""
    page.evaluate(
        """
        () => {
          const findRoot = (root) => {
            for (const el of root.querySelectorAll("*")) {
              if (el.shadowRoot) {
                const view = el.shadowRoot.querySelector(".vvv-root");
                if (view) return view;
                const deeper = findRoot(el.shadowRoot);
                if (deeper) return deeper;
              }
            }
            return null;
          };
          const view =
            document.querySelector(".vvv-root") || findRoot(document);
          if (view) {
            view.scrollIntoView({ block: "start", behavior: "instant" });
          }
        }
        """
    )


def main() -> None:
    url = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_URL
    out = Path(sys.argv[2] if len(sys.argv) > 2 else DEFAULT_OUT)
    out.parent.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel="msedge", headless=True)
        context = browser.new_context(
            viewport={"width": 1480, "height": 1100},
            device_scale_factor=1,
        )
        page = context.new_page()
        page.goto(url, wait_until="domcontentloaded", timeout=90000)
        page.wait_for_selector(".jp-Notebook", timeout=90000)
        page.wait_for_timeout(1500)

        tab = page.locator(".lm-TabBar-tab", has_text="jupyter_demo.ipynb").first
        if tab.count():
            tab.click()
        page.locator(".jp-Notebook").click(position={"x": 480, "y": 240})
        page.wait_for_timeout(300)

        # Drop stale outputs so the wait below only sees this run's widget.
        page.get_by_role("menuitem", name="Edit", exact=True).click()
        page.get_by_role(
            "menuitem", name="Clear Outputs of All Cells", exact=False
        ).click()
        page.wait_for_timeout(500)

        page.get_by_role("menuitem", name="Run", exact=True).click()
        # Fresh kernel so the updated panel assets are imported by the kernel.
        page.get_by_role(
            "menuitem", name="Restart Kernel and Run All Cells", exact=False
        ).click()
        page.wait_for_timeout(800)
        restart = page.locator("button:visible", has_text="Restart")
        if restart.count():
            restart.last.click(timeout=5000)
        page.wait_for_function(
            r"() => /已记录\s*800\s*行/.test(document.body.innerText)",
            timeout=120000,
        )
        page.wait_for_timeout(2000)
        scroll_widget_into_view(page)
        page.wait_for_timeout(600)
        page.screenshot(path=str(out))

        # Persist outputs + widget state so reopening the notebook shows the
        # live dual-pane view even in a fresh browser session.
        page.keyboard.press("Control+S")
        page.wait_for_timeout(1200)

        stats = page.evaluate(
            r"""
            () => {
              const text = document.body.innerText;
              const rows = text.match(/rows recorded:\s*\d+/);
              const csv = text.match(/csv path\s*:\s*[^\n]+/);
              return { rows: rows ? rows[0] : null, csv: csv ? csv[0] : null };
            }
            """
        )
        print(f"screenshot: {out}")
        print(f"stats: {stats}")
        browser.close()


if __name__ == "__main__":
    main()
