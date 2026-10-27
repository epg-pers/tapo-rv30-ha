"""The map card's control row in a headless browser where Playwright is there: while the robot
drives home, Stop is there to cancel the trip and Start (a new whole-home clean) is not the
highlighted button."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

CARD = Path(__file__).resolve().parent.parent / "custom_components" / "tapo_rv30" / "frontend" / "tapo-rv30-card.js"
NODE = shutil.which("node")


def _has_playwright() -> bool:
    if not NODE:
        return False
    try:
        subprocess.run([NODE, "-e", "require('playwright')"], check=True, capture_output=True, timeout=30)
        return True
    except (subprocess.SubprocessError, OSError):
        return False


CONTROLS = r"""
const { chromium } = require("playwright"), fs = require("fs");
const [cardPath] = process.argv.slice(1);
(async () => {
  const browser = await chromium.launch(), page = await browser.newPage({ viewport: { width: 500, height: 900 } });
  const errors = []; page.on("pageerror", (e) => errors.push(e.message));
  await page.setContent(`<!doctype html><body style="margin:0"></body>`);
  await page.addScriptTag({ content: fs.readFileSync(cardPath, "utf8") });
  const out = {};
  const setState = (state) => page.evaluate((state) => {
    const S = (id, attrs = {}, st = "unknown") => ({ entity_id: id, state: st, attributes: attrs, last_updated: "t1" });
    window.services = window.services || [];
    window.c.hass = { states: { "vacuum.robot": S("vacuum.robot", { friendly_name: "Robot", run_busy: null }, state) },
      entities: { "vacuum.robot": { entity_id: "vacuum.robot", device_id: "d", platform: "tapo_rv30" } }, devices: { d: { name: "Robot" } },
      callService: async (d, s, data, target) => { window.services.push({ d, s, target }); },
      fetchWithAuth: () => Promise.reject(new Error("no")), hassUrl: (u) => u };
  }, state);
  const controls = () => page.evaluate(() => [...window.c.shadowRoot.querySelectorAll(".controls .ctl")].map((b) =>
    ({ label: b.textContent.trim(), disabled: b.hasAttribute("disabled"), primary: b.classList.contains("primary") })));
  await page.evaluate(() => { const c = document.createElement("tapo-rv30-card"); window.c = c; c.setConfig({ entity: "vacuum.robot" }); document.body.appendChild(c); });
  for (const state of ["docked", "returning"]) { await setState(state); await page.waitForTimeout(100); out[state] = await controls(); }
  await page.evaluate(() => [...window.c.shadowRoot.querySelectorAll(".controls .ctl")].find((b) => b.textContent.trim() === "Stop").click());
  await page.waitForTimeout(100);
  out.services = await page.evaluate(() => window.services.map((x) => [x.d, x.s, x.target]));
  out.errors = errors;
  console.log(JSON.stringify(out));
  await browser.close();
})();
"""


@pytest.mark.skipif(not _has_playwright(), reason="playwright for node not installed")
def test_stop_cancels_the_trip_home_and_start_is_not_highlighted():
    try:
        run = subprocess.run([NODE, "-e", CONTROLS, str(CARD)], capture_output=True, text=True, check=True, timeout=120)
    except subprocess.CalledProcessError as exc:
        if "Executable doesn't exist" in exc.stderr or "browserType.launch" in exc.stderr:
            pytest.skip("no browser for playwright")
        raise
    out = json.loads(run.stdout.strip().splitlines()[-1])
    assert out["errors"] == []
    docked = {b["label"]: b for b in out["docked"]}
    assert docked["Start"]["primary"] is True and docked["Stop"]["disabled"] is True
    returning = {b["label"]: b for b in out["returning"]}
    assert "Pause" not in returning
    assert returning["Start"]["primary"] is False and returning["Start"]["disabled"] is False
    assert returning["Stop"]["disabled"] is False
    assert not any(b["primary"] for b in out["returning"])
    assert out["services"] == [["vacuum", "stop", {"entity_id": "vacuum.robot"}]]
