"""The map editor's select tool: a virtual wall is hit only near the wall itself, not anywhere
along the endless line through its ends, so a zone under that line stays selectable. Runs
under node against the real file, with the DOM stubbed."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

PANEL = Path(__file__).resolve().parent.parent / "custom_components" / "tapo_rv30" / "frontend" / "tapo-rv30-panel.js"
NODE = shutil.which("node")

pytestmark = pytest.mark.skipif(not NODE, reason="node not installed")

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
const p = Object.create(Panel.prototype);
p._editMm2Px = (x, y) => [x, y];              // canvas px = mm, for the test
const box = (x0, y0, x1, y1) => [[x0, y0], [x1, y0], [x1, y1], [x0, y1]];
p._edit = { furniture: [], areas: {
  forbid: [{ vertexs: box(500, 150, 700, 250) }],                 // a no-go zone well past the wall's end
  virtual_wall: [{ vertexs: [[100, 200], [160, 200]] }, { vertexs: [[300, 0], [300, 50], [350, 50]] }] } };
const hit = (x, y) => { const h = p._editHit(x, y); return h ? h.kind + ":" + h.i : null; };
console.log(JSON.stringify({ onWall: hit(130, 203), pastEnd: hit(560, 203), beforeStart: hit(10, 197),
  secondLeg: hit(330, 52), offBend: hit(400, 52) }));
"""


def test_a_wall_is_hit_only_near_itself():
    run = subprocess.run([NODE, "-e", SCRIPT, str(PANEL)], capture_output=True, text=True, check=True, timeout=60)
    got = json.loads(run.stdout.strip().splitlines()[-1])
    assert got["onWall"] == "virtual_wall:0"
    assert got["pastEnd"] == "forbid:0"          # the zone under the wall's line, not the wall
    assert got["beforeStart"] is None
    assert got["secondLeg"] == "virtual_wall:1"  # every segment of a bent wall counts
    assert got["offBend"] is None
