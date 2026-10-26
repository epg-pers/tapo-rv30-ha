"""The sidebar page's Presets tab: the plain helpers it is built on (room sizes from outlines,
the time estimate from past cleans, copy names, reordering) run under node against the real
file, and a render of the list and the editor in a headless browser where Playwright is there."""
import base64
import io
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from PIL import Image

PANEL = Path(__file__).resolve().parent.parent / "custom_components" / "tapo_rv30" / "frontend" / "tapo-rv30-panel.js"
NODE = shutil.which("node")

# Loads the panel file as it is shipped (DOM stubbed) and hands back its top-level helpers.
LOADER = r"""
const vm = require("vm"), fs = require("fs");
const mk = () => ({ classList: { toggle() {}, add() {} }, style: {}, dataset: {}, querySelector: () => mk(), querySelectorAll: () => [] });
const defs = {};
const ctx = { console, Math, JSON, Number, String, Set, Map, Object, Array, Promise, Int16Array,
  HTMLElement: class { attachShadow() { this.shadowRoot = mk(); return this.shadowRoot; } },
  customElements: { get: (n) => defs[n], define: (n, c) => { defs[n] = c; } }, CustomEvent: class {}, document: { createElement: mk } };
ctx.window = ctx;
vm.createContext(ctx);
const H = vm.runInContext(fs.readFileSync(process.argv[1], "utf8") + `
;({ mmToPx, pxToMm, polyArea, inPoly, polyLabel, moveItem, foldName, uniqueCopyName, cleanPace, presetEstimate, levelSummary, fanLevels,
    Panel: customElements.get("tapo-rv30-panel") })`, ctx);
"""


def _node(body: str):
    run = subprocess.run([NODE, "-e", LOADER + body, str(PANEL)], capture_output=True, text=True, check=True)
    return json.loads(run.stdout.strip().splitlines()[-1])


pytestmark = pytest.mark.skipif(not NODE, reason="node not installed")


def test_file_parses():
    subprocess.run([NODE, "--check", str(PANEL)], check=True)


def test_polygon_area_and_inside():
    out = _node(r"""
const sq = [[0, 0], [1000, 0], [1000, 2000], [0, 2000]], L = [[0, 0], [3000, 0], [3000, 1000], [1000, 1000], [1000, 3000], [0, 3000]];
console.log(JSON.stringify({ sq: H.polyArea(sq), back: H.polyArea([...sq].reverse()), tri: H.polyArea([[0, 0], [4, 0], [0, 3]]),
  none: H.polyArea([]), nul: H.polyArea(null), L: H.polyArea(L),
  inL: H.inPoly(500, 2500, L), notL: H.inPoly(2000, 2000, L), labelSq: H.polyLabel(sq), labelL: H.polyLabel(L),
  labelInL: H.inPoly(...H.polyLabel(L), L) }));""")
    assert out["sq"] == out["back"] == 2_000_000          # mm2: 2 m2, either way round
    assert out["tri"] == 6 and out["none"] == 0 and out["nul"] == 0
    assert out["L"] == 5_000_000
    assert out["inL"] is True and out["notL"] is False
    assert out["labelSq"] == [500, 1000]
    assert out["labelInL"] is True                         # the badge of an L-shaped room lands inside it


def test_l_whose_centroid_is_outside_gets_a_label_inside():
    out = _node(r"""
// A thin L: the centroid falls in the empty corner.
const L = [[0, 0], [5000, 0], [5000, 300], [300, 300], [300, 5000], [0, 5000]];
const c = H.polyLabel(L);
console.log(JSON.stringify({ c, inside: H.inPoly(c[0], c[1], L) }));""")
    assert out["inside"] is True


def test_mm_px_round_trip_matches_the_map_editor():
    out = _node(r"""
const res = [];
for (const rotation of [0, 90, 180, 270]) {
  const g = { scale_px_per_cell: 4, resolution_mm: 50, real_origin_mm: [-3000, -2500], grid_size: [120, 100], rotation };
  for (const [x, y] of [[0, 0], [-2950, 2400], [1500, -2000]]) {
    const p = H.mmToPx(x, y, g), back = H.pxToMm(p[0], p[1], g);
    const ed = H.Panel.prototype._editMm2Px.call({ _edit: { geom: g } }, x, y);
    res.push(back[0] === x && back[1] === y && ed[0] === p[0] && ed[1] === p[1]);
  }
}
console.log(JSON.stringify(res));""")
    assert all(out) and len(out) == 12


def test_reorder():
    out = _node(r"""
const a = ["a", "b", "c", "d"];
console.log(JSON.stringify({ down: H.moveItem(a, 0, 2), up: H.moveItem(a, 3, 0), clampHi: H.moveItem(a, 1, 99), clampLo: H.moveItem(a, 2, -5),
  bad: H.moveItem(a, 7, 0), same: H.moveItem(a, 1, 1), orig: a }));""")
    assert out["down"] == ["b", "c", "a", "d"]
    assert out["up"] == ["d", "a", "b", "c"]
    assert out["clampHi"] == ["a", "c", "d", "b"] and out["clampLo"] == ["c", "a", "b", "d"]
    assert out["bad"] == out["same"] == out["orig"] == ["a", "b", "c", "d"]


def test_unique_copy_name():
    out = _node(r"""
const long = "x".repeat(40);
console.log(JSON.stringify({
  free: H.uniqueCopyName("Mop", ["Mop"]),
  taken: H.uniqueCopyName("Mop", ["Mop", "mop COPY", " Mop copy 2 "]),
  accents: H.uniqueCopyName("Kuchyna", ["Kuchy\u0148a copy"]),
  long: H.uniqueCopyName(long, [long]), long2: H.uniqueCopyName(long, [long, "x".repeat(35) + " copy"]),
  trims: H.uniqueCopyName("  Hall  ", []) }));""")
    assert out["free"] == "Mop copy"
    assert out["taken"] == "Mop copy 3"
    assert out["accents"] == "Kuchyna copy 2"            # names compare without accents or case
    assert out["long"] == "x" * 35 + " copy" and len(out["long"]) == 40
    assert out["long2"] == "x" * 33 + " copy 2" and len(out["long2"]) == 40
    assert out["trims"] == "Hall copy"


def test_estimate_from_past_cleans():
    out = _node(r"""
const runs = [
  { area: 30, minutes: 30, map_id: 1 }, { area: 20, minutes: 10, map_id: 1 },
  { area: 0, minutes: 40, map_id: 1 }, { area: 12, minutes: 4, map_id: 1 },     // no area; too short
  { area: 50, minutes: 100, map_id: 2 }, { area: null, minutes: 20 } ];
const rooms = [{ id: 1, passes: 1 }, { id: 2, passes: 2 }, { id: 9, passes: 1 }];
const areas = { 1: 10, 2: 5 };
console.log(JSON.stringify({
  pace: H.cleanPace(runs, 1), est: H.presetEstimate(rooms, areas, runs, 1),
  // The map's own runs win once it has three usable ones.
  own: H.cleanPace([...runs, { area: 40, minutes: 20, map_id: 1 }], 1),
  none: H.presetEstimate(rooms, areas, [{ area: 5, minutes: 2 }], 1),
  empty: H.presetEstimate([], areas, runs, 1), unknownOnly: H.presetEstimate([{ id: 9, passes: 1 }], areas, runs, 1) }));""")
    # Two map 1 runs are usable, fewer than three, so all three usable runs count: 100 m2 in 140 min.
    assert out["pace"]["runs"] == 3 and out["pace"]["perMin"] == pytest.approx(100 / 140)
    assert out["est"]["m2"] == 20 and out["est"]["unknown"] == 1          # 10 + 5 x 2 passes
    assert out["est"]["minutes"] == round(20 / (100 / 140)) and out["est"]["runs"] == 3
    assert out["own"]["runs"] == 3 and out["own"]["perMin"] == pytest.approx(90 / 60)
    assert out["none"]["minutes"] is None and out["none"]["runs"] == 0 and out["none"]["m2"] == 20
    assert out["empty"] == {"m2": 0, "unknown": 0, "minutes": None, "runs": 3}
    assert out["unknownOnly"]["minutes"] is None and out["unknownOnly"]["unknown"] == 1


def test_levels_summary_and_suction_choices():
    out = _node(r"""
console.log(JSON.stringify({
  same: H.levelSummary([{ suction: 2, water: 2, passes: 1 }, { suction: 2, water: 2, passes: 1 }]),
  mixed: H.levelSummary([{ suction: 3, water: 0, passes: 2 }, { suction: 4, water: 0, passes: 1 }, { suction: 3, water: 1, passes: 1 }]),
  four: H.fanLevels([{ rooms: [{ suction: 4 }] }]), five: H.fanLevels([{ rooms: [{ suction: 1 }] }, { rooms: [{ suction: 5 }] }]), none: H.fanLevels(null) }));""")
    assert out["same"] == "Standard, water medium, 1x"
    assert out["mixed"] == "Turbo/Max, water off/low, 2x/1x"
    assert out["four"] == [1, 2, 3, 4] and out["none"] == [1, 2, 3, 4]
    assert out["five"] == [1, 2, 3, 4, 5]


# ---- render smoke test in a real browser -----------------------------------------------------
def _has_playwright() -> bool:
    if not NODE:
        return False
    try:
        subprocess.run([NODE, "-e", "require('playwright')"], check=True, capture_output=True, timeout=30)
        return True
    except (subprocess.SubprocessError, OSError):
        return False


def _picture() -> str:
    # A 40 x 40 px map (10 x 10 cells of 50 mm, 4 px each): room 1 the left half, room 2 the right.
    img = Image.new("RGBA", (40, 40), (255, 179, 186, 255))
    img.paste((186, 225, 255, 255), (20, 0, 40, 40))
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


SMOKE = r"""
const { chromium } = require("playwright"), fs = require("fs");
const [panelPath, picture, admin] = process.argv.slice(1);
(async () => {
  const browser = await chromium.launch(), page = await browser.newPage({ viewport: { width: 1100, height: 1400 } });
  const errors = []; page.on("pageerror", (e) => errors.push(e.message));
  await page.setContent(`<!doctype html><body></body>`);
  await page.evaluate(([picture, admin]) => {
    customElements.define("tapo-rv30-card", class extends HTMLElement { setConfig(c) { this._config = c; } set hass(h) {} });
    const S = (id, attrs = {}, state = "unknown") => ({ entity_id: id, state, attributes: attrs });
    const states = {
      "vacuum.robot": S("vacuum.robot", { friendly_name: "Robot", integration: "tapo_rv30" }, "docked"),
      "camera.robot_map": S("camera.robot_map", { map_id: 1, maps: [{ id: 1, name: "Down", current: true }, { id: 2, name: "Up", current: false }] }),
      "sensor.robot_schedules": S("sensor.robot_schedules", { schedules: [] }),
      "button.robot_preset_mop": S("button.robot_preset_mop", { friendly_name: "Robot Preset Mop", preset_id: 3, preset_name: "Mop", rooms: ["Left"] }),
    };
    const entities = {}; for (const id in states) entities[id] = { entity_id: id, device_id: "d", platform: "tapo_rv30" };
    entities["button.robot_preset_mop"].translation_key = "preset";
    window.ws = []; window.services = []; window.confirms = []; window.fail = null;
    window.presets = [
      { id: 3, map_id: 1, name: "Mop", clean_order: true, valid: true, rooms: [{ id: 1, name: "Left", suction: 1, water: 3, passes: 1 }, { id: 2, name: "Right <b>", suction: 1, water: 3, passes: 2 }],
        schedules: [{ id: 7, time: "08:00", days: ["Mon", "Tue"], enabled: true }] },
      { id: 3, map_id: 2, name: "Upstairs mop", clean_order: false, valid: false, rooms: [{ id: 5, name: "Landing", suction: 5, water: 0, passes: 1 }], schedules: [] }];
    window.confirm = (t) => { window.confirms.push(t); return true; };
    window.hass = { states, entities, devices: { d: { name: "Robot" } }, user: { is_admin: admin === "1" },
      callService: async (d, s, data, target) => { window.services.push({ d, s, data, target }); },
      callWS: async (m) => {
        window.ws.push(m);
        if (m.type === "tapo_rv30/preset/list") return { maps: [{ id: 1, name: "Down", current: true }, { id: 2, name: "Up", current: false }], presets: window.presets };
        if (m.type === "tapo_rv30/history/list") return { runs: [{ area: 20, minutes: 10, map_id: 1 }, { area: 10, minutes: 3, map_id: 1 }] };
        if (m.type === "tapo_rv30/map/edit_get") return { map_id: m.map_id, current: m.map_id === 1, picture,
          geometry: { scale_px_per_cell: 4, resolution_mm: 50, real_origin_mm: [0, 0], grid_size: [10, 10], image_size: [40, 40], rotation: 0 },
          rooms: [{ id: 1, name: "Left", vertexs: [[0, 0], [250, 0], [250, 500], [0, 500]] }, { id: 2, name: "Right <b>", vertexs: [[250, 0], [500, 0], [500, 500], [250, 500]] }] };
        if (m.type === "tapo_rv30/preset/save") { if (window.fail) throw { message: window.fail }; return { preset_id: 9, name: m.name, map_id: m.map_id }; }
        throw { message: "unknown " + m.type };
      },
      connection: { subscribeEvents: async () => () => {}, subscribeMessage: async () => () => {} } };
  }, [picture, admin]);
  await page.addScriptTag({ content: fs.readFileSync(panelPath, "utf8") });
  const out = {};
  const R = (sel) => page.evaluate((sel) => { const r = window.p.shadowRoot; return [...r.querySelectorAll(sel)].map((e) => e.textContent.trim()); }, sel);
  const click = async (sel, i = 0) => { await page.evaluate(([sel, i]) => window.p.shadowRoot.querySelectorAll(sel)[i].click(), [sel, i]); await page.waitForTimeout(150); };
  await page.evaluate(() => { const p = document.createElement("tapo-rv30-panel"); window.p = p; document.body.appendChild(p); p.narrow = false; p.hass = window.hass; });
  await page.waitForTimeout(200);
  out.tabs = await R(".tabs button");
  await click('.tabs [data-tab="presets"]'); await page.waitForTimeout(200);
  out.listCalls = (await page.evaluate(() => window.ws.filter((m) => m.type === "tapo_rv30/preset/list").length));
  out.titles = await R(".prow .t"); out.groups = await R(".pane h5");
  out.rows = await page.evaluate(() => [...window.p.shadowRoot.querySelectorAll(".prow .s")].map((e) => e.innerHTML));
  out.delDisabled = await page.evaluate(() => [...window.p.shadowRoot.querySelectorAll('[data-act="del"]')].map((b) => b.disabled));
  // A state update that leaves the preset buttons alone does not read the list again.
  await page.evaluate(() => { window.hass = { ...window.hass, states: { ...window.hass.states, "vacuum.robot": { ...window.hass.states["vacuum.robot"], state: "cleaning" } } }; window.p.hass = window.hass; });
  await page.waitForTimeout(150);
  out.listCallsAfterUpdate = (await page.evaluate(() => window.ws.filter((m) => m.type === "tapo_rv30/preset/list").length));
  // Run and delete (with the schedules that run it named).
  await click('[data-act="run"]');
  if (admin === "1") await click('[data-act="del"]');
  out.confirms = await page.evaluate(() => window.confirms); out.services = await page.evaluate(() => window.services);
  // Duplicate: a free name and no preset id; tap the right room on the map to take it out.
  await page.waitForTimeout(150);
  await click('.prow [data-act="dup"]'); await page.waitForTimeout(400);
  out.dupName = await page.evaluate(() => window.p.shadowRoot.querySelector(".pname").value);
  out.picked = await R(".pk:not(.all) .nm");
  const box = await page.evaluate(() => { const r = window.p.shadowRoot.querySelector(".pcanvas").getBoundingClientRect(); return [r.left, r.top, r.width, r.height]; });
  await page.mouse.click(box[0] + box[2] * 0.75, box[1] + box[3] * 0.5); await page.waitForTimeout(150);
  out.afterTap = await R(".pk:not(.all) .nm");
  await page.mouse.click(box[0] + box[2] * 0.75, box[1] + box[3] * 0.5); await page.waitForTimeout(150);
  out.afterTap2 = await R(".pk:not(.all) .nm");
  await click('.pk[data-id="2"] [data-mv="-1"]');
  out.moved = await R(".pk:not(.all) .nm");
  out.badges = await R(".pk:not(.all) .num");
  out.estimate = (await R(".pest"))[0];
  out.fans = await page.evaluate(() => [...window.p.shadowRoot.querySelectorAll('.pk[data-id="1"] select[data-k="suction"] option')].map((o) => o.textContent));
  // An open editor survives a state update.
  await page.evaluate(() => { window.p.hass = { ...window.hass }; });
  out.stillOpen = await page.evaluate(() => !!window.p.shadowRoot.querySelector(".pname"));
  // A refused save shows the integration's message; a good one returns to the list.
  await page.evaluate((m) => { window.fail = m; }, "a preset called 'Mop copy' already exists on that map");
  await click(".save"); await page.waitForTimeout(150);
  out.err = (await R(".err"))[0];
  await page.evaluate(() => { window.fail = null; }); await click(".save"); await page.waitForTimeout(300);
  out.saved = await page.evaluate(() => window.ws.filter((m) => m.type === "tapo_rv30/preset/save").pop());
  out.backToList = await page.evaluate(() => !window.p.shadowRoot.querySelector(".pname") && !!window.p.shadowRoot.querySelector(".prow"));
  out.listCallsAfterSave = (await page.evaluate(() => window.ws.filter((m) => m.type === "tapo_rv30/preset/list").length));
  // Schedule: hands over to a new schedule on the Schedules tab, set to this preset.
  await click('.prow [data-act="sched"]'); await page.waitForTimeout(200);
  out.sched = await page.evaluate(() => ({ tab: window.p._tab, title: window.p.shadowRoot.querySelector(".pane h3").textContent.trim(),
    preset: window.p.shadowRoot.querySelector("select.preset").value, mode: window.p.shadowRoot.querySelector(".mode .on").dataset.mode }));
  out.errors = errors;
  console.log(JSON.stringify(out));
  await browser.close();
})();
"""


@pytest.mark.skipif(not _has_playwright(), reason="playwright for node not installed")
@pytest.mark.parametrize("admin", [True, False])
def test_presets_tab_renders_and_edits(admin):
    try:
        run = subprocess.run([NODE, "-e", SMOKE, str(PANEL), _picture(), "1" if admin else "0"],
                             capture_output=True, text=True, check=True, timeout=120)
    except subprocess.CalledProcessError as exc:
        if "Executable doesn't exist" in exc.stderr or "browserType.launch" in exc.stderr:
            pytest.skip("no browser for playwright")
        raise
    out = json.loads(run.stdout.strip().splitlines()[-1])
    assert out["errors"] == []
    assert out["tabs"][:3] == ["Schedules", "Presets", "Planner"]
    assert out["listCalls"] == 1 and out["listCallsAfterUpdate"] == 1
    assert out["titles"] == ["Mop in order", "Upstairs mop"]
    assert out["groups"] == ["Down (current map)", "Up"]
    # Room names are escaped, in order with arrows; levels and schedules summarised.
    assert out["rows"][0] == "Left \u2192 Right &lt;b&gt;"
    assert out["rows"][1].startswith("Quiet, water high, 1x/2x") and "1 schedule" in out["rows"][1]
    assert out["delDisabled"] == [not admin, not admin]
    assert out["confirms"][0] == "Start Mop now? The robot will leave the dock."
    calls = [(s["s"], s["data"]) for s in out["services"]]
    assert calls[0] == ("run_preset", {"preset": 3, "map": 1})
    if admin:
        assert "Schedules that run it (08:00 Mon Tue) will be left pointing at nothing" in out["confirms"][1]
        assert calls[1] == ("delete_preset", {"preset": 3, "map": 1, "confirm": True})
    else:
        assert len(calls) == 1
    assert out["dupName"] == "Mop copy"
    assert out["picked"] == ["Left", "Right <b>"]
    assert out["afterTap"] == ["Left"] and out["afterTap2"] == ["Left", "Right <b>"]
    assert out["moved"] == ["Right <b>", "Left"] and out["badges"] == ["1", "2"]
    # 0.125 m2 per room; Right came back with the last row's levels when the editor opened (its
    # own, 2 passes): 0.375 m2 at 2 m2 a minute, from the one run of 5 minutes or more.
    assert out["estimate"].startswith("Estimate: about 0.4 m") and "counting every pass" in out["estimate"]
    assert "around 1 min" in out["estimate"] and "(from 1 past clean)" in out["estimate"]
    assert out["fans"] == ["Quiet", "Standard", "Turbo", "Max", "Ultra"]       # Ultra: a preset already uses it
    assert out["stillOpen"] is True
    assert out["err"] == "a preset called 'Mop copy' already exists on that map"
    saved = out["saved"]
    assert "preset_id" not in saved and saved["map_id"] == 1 and saved["name"] == "Mop copy" and saved["clean_order"] is True
    assert saved["rooms"] == [{"id": 2, "suction": 1, "water": 3, "passes": 2}, {"id": 1, "suction": 1, "water": 3, "passes": 1}]
    assert out["backToList"] is True and out["listCallsAfterSave"] >= 2
    assert out["sched"] == {"tab": "schedules", "title": "New schedule", "preset": "3", "mode": "preset"}
