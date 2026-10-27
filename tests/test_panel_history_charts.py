"""The sidebar page's History tab: the charts count the same runs as the list below them (kept
clean maps plus the robot's own runs), not only the robot's few records. Runs under node
against the real file, with the DOM stubbed."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

PANEL = Path(__file__).resolve().parent.parent / "custom_components" / "tapo_rv30" / "frontend" / "tapo-rv30-panel.js"
NODE = shutil.which("node")

pytestmark = pytest.mark.skipif(not NODE, reason="node not installed")

# Loads the panel as shipped, opens the History tab on a stub pane and reports what each chart drew.
SCRIPT = r"""
const vm = require("vm"), fs = require("fs");
const mk = () => ({ classList: { toggle() {}, add() {} }, style: {}, dataset: {}, querySelector: () => mk(), querySelectorAll: () => [] });
const defs = {};
const ctx = { console, Math, JSON, Number, String, Set, Map, Object, Array, Promise, Date, Int16Array,
  HTMLElement: class { attachShadow() { this.shadowRoot = mk(); return this.shadowRoot; } },
  customElements: { get: (n) => defs[n], define: (n, c) => { defs[n] = c; } }, CustomEvent: class {}, document: { createElement: mk } };
ctx.window = ctx;
vm.createContext(ctx);
const Panel = vm.runInContext(fs.readFileSync(process.argv[1], "utf8") + `;customElements.get("tapo-rv30-panel")`, ctx);
const withHistory = process.argv[2] === "1";

// Noon local time, k days ago.
const at = (k) => { const t = new Date(); t.setHours(12, 0, 0, 0); t.setDate(t.getDate() - k); return Math.floor(t.getTime() / 1000); };
// The robot holds only its last two runs; the kept maps reach back six weeks. Run 10 days ago
// has no minutes recorded; the run 40 days ago is outside the 30 day chart but inside 8 weeks.
const recs = [{ started: at(0), minutes: 30, area: 20 }, { started: at(1), minutes: 30, area: 20 }];
const runs = [
  { started: at(0), minutes: 30, area: 20, kept: true, on_robot: true },
  { started: at(1), minutes: 30, area: 20, kept: true, on_robot: true },
  { started: at(3), minutes: 30, area: 20, kept: true, on_robot: false },
  { started: at(10), area: 20, kept: true, on_robot: false },
  { started: at(20), minutes: 30, area: 20, kept: true, on_robot: false },
  { started: at(40), minutes: 30, area: 20, kept: true, on_robot: false },
];

const p = Object.create(Panel.prototype), charts = {};
p._robot = "vacuum.robot";
p._related = () => ({ totals: { cleans: "sensor.c", area: "sensor.a", time: "sensor.t" } });
p._st = () => ({ state: "42" });
p._renderRuns = () => {};
p._chart = (canvas, values) => { charts[canvas.sel] = values; };
p._hass = {
  connection: { sendMessagePromise: async () => ({ response: { records: recs } }) },
  callWS: async (m) => { if (withHistory && m.type === "tapo_rv30/history/list") return { runs, retention: "3 months" }; throw { message: "unknown " + m.type }; },
};
const pane = { innerHTML: "", querySelector: (sel) => ({ sel }) };
p._paneHistory(pane).then(() => console.log(JSON.stringify(charts)));
"""


def _charts(with_history: bool) -> dict:
    run = subprocess.run([NODE, "-e", SCRIPT, str(PANEL), "1" if with_history else "0"],
                         capture_output=True, text=True, check=True, timeout=60)
    return json.loads(run.stdout.strip().splitlines()[-1])


def test_charts_count_kept_runs_not_only_the_robots_records():
    out = _charts(True)
    days, weeks = out["canvas.days"], out["canvas.weeks"]
    assert len(days) == 30 and len(weeks) == 8
    # Five runs in the last 30 days (today, 1, 3, 10 and 20 days ago), each counted once even
    # where the robot also has it.
    assert sum(days) == 5
    assert days[29] == 1 and days[28] == 1 and days[26] == 1 and days[19] == 1 and days[9] == 1
    # Minutes over 8 weeks: five runs of 30; the one without minutes adds nothing.
    assert sum(weeks) == 150


def test_charts_fall_back_to_the_robots_records_without_history():
    out = _charts(False)
    assert sum(out["canvas.days"]) == 2 and out["canvas.days"][29] == 1 and out["canvas.days"][28] == 1
    assert sum(out["canvas.weeks"]) == 60
