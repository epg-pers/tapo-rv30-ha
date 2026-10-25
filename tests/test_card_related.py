"""The map card finds its device's other entities again when the entity registry changes, so a
preset button added after the card first rendered gets its chip without a browser reload, and
looking again keeps what the user has selected or drawn on the map."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

CARD = Path(__file__).resolve().parent.parent / "custom_components" / "tapo_rv30" / "frontend" / "tapo-rv30-card.js"

# Minimal DOM stubs, enough for the card to build and render under node.
SCRIPT = r"""
const mk = () => ({ classList: { toggle() {}, add() {}, remove() {}, contains() { return false; } }, style: { setProperty() {} },
  dataset: {}, kids: [], hidden: false, textContent: "", innerHTML: "", title: "", className: "",
  querySelector: () => mk(), querySelectorAll: () => [],
  appendChild(c) { this.kids.push(c); return c; }, addEventListener() {}, setAttribute() {}, removeAttribute() {},
  getContext: () => null, firstElementChild: { style: {} }, remove() {}, focus() {} });
const defs = {};
globalThis.HTMLElement = class { attachShadow() { this.shadowRoot = mk(); return this.shadowRoot; } dispatchEvent() {} get isConnected() { return true; } };
globalThis.customElements = { get: (n) => defs[n], define: (n, c) => { defs[n] = c; } };
globalThis.window = globalThis;
globalThis.CustomEvent = class {};
globalThis.document = { createElement: () => mk() };
globalThis.Image = class {};
globalThis.requestAnimationFrame = () => 0;
const log = console.info; console.info = () => {};
require(process.argv[1]);
console.info = log;

const Card = defs["tapo-rv30-card"], dev = "dev1";
const st = (id, attrs = {}, t = "t1") => ({ entity_id: id, state: "unknown", attributes: attrs, last_updated: t });
const base = (entities, states) => ({
  entities: { "vacuum.robot": { device_id: dev, platform: "tapo_rv30" }, ...entities },
  devices: { [dev]: { name: "Robot" } },
  states: { "vacuum.robot": { ...st("vacuum.robot", { friendly_name: "Robot" }), state: "docked" }, ...states },
  callService: () => Promise.resolve(), fetchWithAuth: () => Promise.reject(new Error("no")), hassUrl: (u) => u,
});
const card = new Card();
card.setConfig({ entity: "vacuum.robot" });
let renders = 0; const render = card._render.bind(card); card._render = () => { renders++; render(); };
const chips = () => JSON.parse(card._chipsKey || "[]").map((c) => c.label);
const out = {};

// No presets yet: the chip row is hidden.
const h1 = base({}, {});
card.hass = h1;
out.hiddenFirst = card._el.chips.hidden;
card._selected.add(3); card._zone = { x0: 1, y0: 2, x1: 3, y1: 4 }; card._target = [5, 6];

// A poll with the same registry looks nothing up again and renders nothing new.
const rel = card._related; renders = 0;
card.hass = { ...h1, states: { ...h1.states } };
out.sameObject = card._related === rel; out.rendersSame = renders;

// A registry update that changes nothing this card shows does not render either.
card.hass = { ...h1, entities: { ...h1.entities } };
out.rendersNoChange = renders;

// create_preset (or a preset added in the app): the next refresh adds its button.
const h2 = base({ "button.robot_preset_kitchen": { device_id: dev, platform: "tapo_rv30" } },
  { "button.robot_preset_kitchen": st("button.robot_preset_kitchen", { friendly_name: "Robot Preset Kitchen", rooms: ["Kitchen"] }) });
card.hass = h2;
out.afterAdd = chips(); out.hiddenAfter = card._el.chips.hidden;

out.kept = { selected: [...card._selected], zone: card._zone, target: card._target };
console.log(JSON.stringify(out));
"""


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_card_picks_up_a_preset_added_after_it_rendered():
    run = subprocess.run(["node", "-e", SCRIPT, str(CARD)], capture_output=True, text=True, check=True)
    out = json.loads(run.stdout.strip().splitlines()[-1])
    assert out["hiddenFirst"] is True
    assert out["sameObject"] is True and out["rendersSame"] == 0
    assert out["rendersNoChange"] == 0
    assert out["afterAdd"] == ["Kitchen"] and out["hiddenAfter"] is False
    assert out["kept"] == {"selected": [3], "zone": {"x0": 1, "y0": 2, "x1": 3, "y1": 4}, "target": [5, 6]}
