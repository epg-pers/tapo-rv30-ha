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


def _png(img: Image.Image) -> str:
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def _maps() -> tuple[str, str]:
    """A 10 x 10 cell map (50 mm cells, 4 px each, so a 40 x 40 px picture) and its room-id grid,
    as the integration sends them. Room 2 is the top right quarter; room 1 is an L around it (the
    left half and the bottom right), so room 1's box holds all of room 2. Both rooms are painted
    the same colour (the palette repeats) and room 1's name sits on it in white: picking must go
    by the grid, never by colour. The bottom left cell is plain floor (255)."""
    pic = Image.new("RGBA", (40, 40), (255, 179, 186, 255))
    pic.paste((255, 255, 255, 255), (4, 18, 16, 22))          # room 1's name, drawn on the picture
    mask = Image.new("L", (10, 10), 1)
    mask.paste(2, (5, 0, 10, 5))
    mask.putpixel((0, 9), 255)
    return _png(pic), _png(mask)


SMOKE = r"""
const { chromium } = require("playwright"), fs = require("fs");
const [panelPath, picture, mask, admin] = process.argv.slice(1);
(async () => {
  const browser = await chromium.launch(), page = await browser.newPage({ viewport: { width: 1100, height: 1400 } });
  const errors = []; page.on("pageerror", (e) => errors.push(e.message));
  await page.setContent(`<!doctype html><body style="margin:0"></body>`);
  await page.evaluate(([picture, mask, admin]) => {
    customElements.define("tapo-rv30-card", class extends HTMLElement { setConfig(c) { this._config = c; } set hass(h) {} });
    const S = (id, attrs = {}, state = "unknown") => ({ entity_id: id, state, attributes: attrs });
    const cells = [{ id: 1, name: "Left", bbox: [0, 0, 39, 39], centre: [10, 20], cells: 75 }, { id: 2, name: "Right <b>", bbox: [20, 0, 39, 19], centre: [30, 10], cells: 25 }];
    const states = {
      "vacuum.robot": S("vacuum.robot", { friendly_name: "Robot", integration: "tapo_rv30", fan_speed: "Turbo", water_level: "low", clean_passes: 1 }, "docked"),
      "camera.robot_map": S("camera.robot_map", { map_id: 1, room_geometry: cells, map_geometry: { resolution_mm: 50 },
        maps: [{ id: 1, name: "Down", current: true }, { id: 2, name: "Up", current: false }] }),
      "sensor.robot_schedules": S("sensor.robot_schedules", { schedules: [] }),
      "button.robot_preset_mop": S("button.robot_preset_mop", { friendly_name: "Robot Preset Mop", preset_id: 3, preset_name: "Mop", rooms: ["Left"] }),
    };
    const entities = {}; for (const id in states) entities[id] = { entity_id: id, device_id: "d", platform: "tapo_rv30" };
    entities["button.robot_preset_mop"].translation_key = "preset";
    window.ws = []; window.services = []; window.confirms = []; window.fail = null; window.editFail = false;
    // Preset 3 is on both maps: ids repeat across maps.
    window.presets = [
      { id: 3, map_id: 1, name: "Mop", clean_order: true, valid: true, rooms: [{ id: 1, name: "Left", suction: 1, water: 3, passes: 1 }, { id: 2, name: "Right <b>", suction: 1, water: 3, passes: 2 }],
        schedules: [{ id: 7, time: "08:00", days: ["Mon", "Tue"], enabled: true }] },
      { id: 3, map_id: 2, name: "Upstairs mop", clean_order: false, valid: false, schedules: [],
        rooms: [{ id: 5, name: "Landing", suction: 5, water: null, passes: 1 }, { id: 6, name: "Stairs", suction: null, water: null, passes: null }] }];
    window.confirm = (t) => { window.confirms.push(t); return true; };
    window.hass = { states, entities, devices: { d: { name: "Robot" } }, user: { is_admin: admin === "1" },
      callService: async (d, s, data, target) => { window.services.push({ d, s, data, target }); },
      callWS: async (m) => {
        window.ws.push(m);
        if (m.type === "tapo_rv30/preset/list") return { maps: [{ id: 1, name: "Down", current: true, saved: true }, { id: 2, name: "Up", current: false, saved: true },
          { id: 4, name: "Being made", current: false, saved: false }], presets: window.presets };
        if (m.type === "tapo_rv30/history/list") return { runs: [{ area: 20, minutes: 10, map_id: 1 }, { area: 10, minutes: 3, map_id: 1 }] };
        if (m.type === "tapo_rv30/map/edit_get") {
          if (window.editFail) throw { message: "the robot is busy" };
          return { map_id: m.map_id, current: m.map_id === 1, picture, room_mask: mask, room_geometry: cells,
            geometry: { scale_px_per_cell: 4, resolution_mm: 50, real_origin_mm: [0, 0], grid_size: [10, 10], image_size: [40, 40], rotation: 0 },
            rooms: [{ id: 1, name: "Left", vertexs: null }, { id: 2, name: "Right <b>", vertexs: null }] };
        }
        if (m.type === "tapo_rv30/preset/save") { if (window.fail) throw { message: window.fail }; return { preset_id: 9, name: m.name, map_id: m.map_id }; }
        throw { message: "unknown " + m.type };
      },
      connection: { subscribeEvents: async () => () => {}, subscribeMessage: async () => () => {} } };
  }, [picture, mask, admin]);
  await page.addScriptTag({ content: fs.readFileSync(panelPath, "utf8") });
  const out = {};
  const R = (sel) => page.evaluate((sel) => [...window.p.shadowRoot.querySelectorAll(sel)].map((e) => e.textContent.trim()), sel);
  const click = async (sel, i = 0) => { await page.evaluate(([sel, i]) => window.p.shadowRoot.querySelectorAll(sel)[i].click(), [sel, i]); await page.waitForTimeout(150); };
  const lists = () => page.evaluate(() => window.ws.filter((m) => m.type === "tapo_rv30/preset/list").length);
  await page.evaluate(() => { const p = document.createElement("tapo-rv30-panel"); window.p = p; document.body.appendChild(p); p.narrow = false; p.hass = window.hass; });
  await page.waitForTimeout(200);
  out.tabs = await R(".tabs button");
  await click('.tabs [data-tab="presets"]'); await page.waitForTimeout(200);
  out.listCalls = await lists();
  out.titles = await R(".prow .t"); out.groups = await R(".pane h5");
  out.mapPicker = await R(".pmap option");
  out.rows = await page.evaluate(() => [...window.p.shadowRoot.querySelectorAll(".prow .s")].map((e) => e.innerHTML));
  out.delDisabled = await page.evaluate(() => [...window.p.shadowRoot.querySelectorAll('[data-act="del"]')].map((b) => b.disabled));
  // A status change that leaves the preset buttons alone neither reads the list again nor redraws it.
  await page.evaluate(() => { window.p.shadowRoot.querySelector(".prow").dataset.mark = "1";
    window.hass = { ...window.hass, states: { ...window.hass.states, "vacuum.robot": { ...window.hass.states["vacuum.robot"], state: "cleaning" } } }; window.p.hass = window.hass; });
  await page.waitForTimeout(150);
  out.listCallsAfterUpdate = await lists();
  out.notRedrawn = await page.evaluate(() => window.p.shadowRoot.querySelector(".prow").dataset.mark === "1");
  // Run and delete (with the schedules that run it named).
  await click('[data-act="run"]');
  if (admin === "1") await click('[data-act="del"]');
  out.confirms = await page.evaluate(() => window.confirms);
  out.services = await page.evaluate(() => window.services.map((x) => [x.s, x.data]));
  await page.waitForTimeout(150);

  // Levels the robot never set: filled from a neighbour or the robot's own setting, and marked.
  await click('.prow [data-act="edit"]', 1); await page.waitForTimeout(400);
  out.unset = await page.evaluate(() => [...window.p.shadowRoot.querySelectorAll(".pk:not(.all) select")].map((s) => [s.dataset.k, Number(s.value), s.classList.contains("unset")]));
  out.unsetNote = (await R(".ppicked .warn"))[0] || "";
  out.unsetLabel = await page.evaluate(() => window.p.shadowRoot.querySelector('.pk[data-id="6"] select[data-k="suction"]').getAttribute("aria-label"));
  await page.evaluate(() => { const s = window.p.shadowRoot.querySelector('.pk[data-id="6"] select[data-k="suction"]'); s.value = "2"; s.dispatchEvent(new Event("change", { bubbles: true })); });
  out.unsetAfterPick = await page.evaluate(() => window.p.shadowRoot.querySelector('.pk[data-id="6"] select[data-k="suction"]').classList.contains("unset"));
  await click(".cancel");

  // Duplicate: a free name and no preset id; rooms picked on the map by the room-id grid.
  await click('.prow [data-act="dup"]'); await page.waitForTimeout(400);
  out.dupName = await page.evaluate(() => window.p.shadowRoot.querySelector(".pname").value);
  out.picked = await R(".pk:not(.all) .nm");
  const box = await page.evaluate(() => { const r = window.p.shadowRoot.querySelector(".pcanvas").getBoundingClientRect(); return [r.left, r.top, r.width, r.height]; });
  const tap = async (fx, fy) => { await page.mouse.click(box[0] + box[2] * fx, box[1] + box[3] * fy); await page.waitForTimeout(120); return R(".pk:not(.all) .nm"); };
  out.tapRight = await tap(0.75, 0.25);         // room 2, inside room 1's box
  out.tapRightAgain = await tap(0.75, 0.25);
  out.tapArm = await tap(0.75, 0.75);           // room 1's arm under room 2
  out.tapName = await tap(0.25, 0.5);           // room 1's name on the picture
  out.tapFloor = await tap(0.05, 0.95);         // floor that is no room: nothing
  await click('.pk[data-id="1"] [data-mv="-1"]');
  out.moved = await R(".pk:not(.all) .nm");
  out.badges = await R(".pk:not(.all) .num");
  out.estimate = (await R(".pest"))[0];
  out.fans = await page.evaluate(() => [...window.p.shadowRoot.querySelectorAll('.pk[data-id="1"] select[data-k="suction"] option')].map((o) => o.textContent));
  // The tint follows the grid: a pixel of room 1's arm is tinted, the floor cell is not.
  out.tint = await page.evaluate(() => { const c = window.p.shadowRoot.querySelector(".pcanvas").getContext("2d");
    return { arm: [...c.getImageData(30, 30, 1, 1).data], floor: [...c.getImageData(1, 38, 1, 1).data] }; });
  // Medium widths without the narrow layout: nothing runs off the side.
  out.fit = {};
  for (const w of [900, 760]) {
    await page.setViewportSize({ width: w, height: 1400 }); await page.waitForTimeout(200);
    out.fit[w] = await page.evaluate(() => { const s = window.p.shadowRoot.querySelector(".save").getBoundingClientRect();
      return { scroll: document.documentElement.scrollWidth, inner: innerWidth, saveRight: s.right, twoLines: getComputedStyle(window.p.shadowRoot.querySelector(".pk:not(.all) .lv")).gridRowStart === "2" }; });
  }
  await page.setViewportSize({ width: 1100, height: 1400 });
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
  out.listCallsAfterSave = await lists();

  // The map cannot be read: the current map's rooms still come from the camera.
  await page.evaluate(() => { window.editFail = true; });
  await click('.tabs [data-tab="presets"]'); await page.waitForTimeout(200);
  await click('[data-act="new"]'); await page.waitForTimeout(300);
  out.chipsNoMap = await R(".prooms .chip");
  out.statusNoMap = (await R(".pstatus"))[0];
  await click(".cancel");

  // Schedule: hands over to a new schedule set to this preset, by map and id (3 is on both maps).
  await click('.prow [data-act="sched"]', 1); await page.waitForTimeout(200);
  out.sched = await page.evaluate(() => { const r = window.p.shadowRoot, sel = r.querySelector("select.preset");
    return { tab: window.p._tab, title: r.querySelector(".pane h3").textContent.trim(), preset: sel.value,
      label: sel.selectedOptions[0].textContent, mode: r.querySelector(".mode .on").dataset.mode, groups: [...sel.querySelectorAll("optgroup")].map((g) => g.label) }; });
  await click('[data-quick="daily"]'); await click(".save");
  out.schedCall = await page.evaluate(() => window.services.filter((x) => x.s === "add_schedule").map((x) => x.data).pop());
  out.errors = errors;
  console.log(JSON.stringify(out));
  await browser.close();
})();
"""


@pytest.mark.skipif(not _has_playwright(), reason="playwright for node not installed")
@pytest.mark.parametrize("admin", [True, False])
def test_presets_tab_renders_and_edits(admin):
    picture, mask = _maps()
    try:
        run = subprocess.run([NODE, "-e", SMOKE, str(PANEL), picture, mask, "1" if admin else "0"],
                             capture_output=True, text=True, check=True, timeout=120)
    except subprocess.CalledProcessError as exc:
        if "Executable doesn't exist" in exc.stderr or "browserType.launch" in exc.stderr:
            pytest.skip("no browser for playwright")
        raise
    out = json.loads(run.stdout.strip().splitlines()[-1])
    assert out["errors"] == []
    assert out["tabs"][:3] == ["Schedules", "Presets", "Planner"]
    assert out["listCalls"] == 1 and out["listCallsAfterUpdate"] == 1 and out["notRedrawn"] is True
    assert out["titles"] == ["Mop in order", "Upstairs mop"]
    assert out["groups"] == ["Down (current map)", "Up"]           # the map being made is left out
    assert out["mapPicker"] == ["Down", "Up"]
    # Room names are escaped, in order with arrows; levels and schedules summarised.
    assert out["rows"][0] == "Left \u2192 Right &lt;b&gt;"
    assert out["rows"][1].startswith("Quiet, water high, 1x/2x") and "1 schedule" in out["rows"][1]
    assert out["delDisabled"] == [not admin, not admin]
    assert out["confirms"][0] == "Start Mop now? The robot will leave the dock."
    assert out["services"][0] == ["run_preset", {"preset": 3, "map": 1}]         # by map and id
    if admin:
        assert "Schedules that run it (08:00 Mon Tue) will be left pointing at nothing" in out["confirms"][1]
        assert out["services"][1] == ["delete_preset", {"preset": 3, "map": 1, "confirm": True}]

    # Landing: water unset -> the robot's own (low). Stairs: suction from Landing (Ultra), water
    # from the robot, passes from Landing; every filled-in level marked until it is picked.
    assert out["unset"] == [["suction", 5, False], ["water", 1, True], ["passes", 1, False],
                            ["suction", 5, True], ["water", 1, True], ["passes", 1, True]]
    assert "not set on the robot" in out["unsetNote"] and out["unsetLabel"] == "Suction for Stairs (was unset)"
    assert out["unsetAfterPick"] is False

    assert out["dupName"] == "Mop copy"
    assert out["picked"] == ["Left", "Right <b>"]
    assert out["tapRight"] == ["Left"] and out["tapRightAgain"] == ["Left", "Right <b>"]
    assert out["tapArm"] == ["Right <b>"] and out["tapName"] == ["Right <b>", "Left"]
    assert out["tapFloor"] == ["Right <b>", "Left"]
    assert out["moved"] == ["Left", "Right <b>"] and out["badges"] == ["1", "2"]
    # Sizes from the room cells (75 and 25 of 0.0025 m2); both rooms came back with the last row's
    # levels when the editor opened (2 passes): 0.5 m2 at 2 m2 a minute, from the one long run.
    assert out["estimate"].startswith("Estimate: about 0.5 m") and "counting every pass" in out["estimate"]
    assert "around 1 min" in out["estimate"] and "(from 1 past clean)" in out["estimate"]
    assert out["fans"] == ["Quiet", "Standard", "Turbo", "Max", "Ultra"]       # Ultra: a preset already uses it
    assert out["tint"]["arm"] != [255, 179, 186, 255] and out["tint"]["floor"] == [255, 179, 186, 255]
    for w in ("900", "760"):
        fit = out["fit"][w]
        assert fit["scroll"] <= fit["inner"] and fit["saveRight"] <= fit["inner"], (w, fit)
    assert out["fit"]["760"]["twoLines"] is True
    assert out["stillOpen"] is True
    assert out["err"] == "a preset called 'Mop copy' already exists on that map"
    saved = out["saved"]
    assert "preset_id" not in saved and saved["map_id"] == 1 and saved["name"] == "Mop copy" and saved["clean_order"] is True
    assert saved["rooms"] == [{"id": 1, "suction": 1, "water": 3, "passes": 2}, {"id": 2, "suction": 1, "water": 3, "passes": 2}]
    assert out["backToList"] is True and out["listCallsAfterSave"] >= 2

    assert out["chipsNoMap"] == ["Left", "Right <b>"] and out["statusNoMap"].startswith("Could not read the map (the robot is busy)")

    assert out["sched"] == {"tab": "schedules", "title": "New schedule", "preset": "2:3", "label": "Upstairs mop",
                            "mode": "preset", "groups": ["Down", "Up"]}
    assert out["schedCall"]["preset"] == 3 and out["schedCall"]["map"] == "2"
    assert "rooms" not in out["schedCall"] and "room_ids" not in out["schedCall"]


# The Schedules tab before the Presets tab is ever opened: its presets come from the preset buttons,
# which name each preset's map. Preset 3 is on both maps (ids repeat); 7 is only upstairs; 8 is a
# button from before buttons named their map.
SCHED_FALLBACK = r"""
const { chromium } = require("playwright"), fs = require("fs");
const [panelPath] = process.argv.slice(1);
(async () => {
  const browser = await chromium.launch(), page = await browser.newPage({ viewport: { width: 1100, height: 1200 } });
  const errors = []; page.on("pageerror", (e) => errors.push(e.message));
  await page.setContent(`<!doctype html><body style="margin:0"></body>`);
  await page.evaluate(() => {
    customElements.define("tapo-rv30-card", class extends HTMLElement { setConfig(c) { this._config = c; } set hass(h) {} });
    const S = (id, attrs = {}, state = "unknown") => ({ entity_id: id, state, attributes: attrs });
    const B = (id, attrs) => S(`button.${id}`, { friendly_name: `Robot ${attrs.preset_name}`, ...attrs });
    const states = {
      "vacuum.robot": S("vacuum.robot", { friendly_name: "Robot", integration: "tapo_rv30" }, "docked"),
      "camera.robot_map": S("camera.robot_map", { map_id: 1, maps: [{ id: 1, name: "Down", current: true }, { id: 2, name: "Up", current: false }] }),
      "sensor.robot_schedules": S("sensor.robot_schedules", { schedules: [
        { id: 5, time: "08:00", days: ["Mon"], enabled: true, preset_id: 3, map_id: 1 }] }),
      "button.robot_preset_mop": B("robot_preset_mop", { preset_id: 3, preset_name: "Mop", map_id: 1, map_name: "Down" }),
      "button.robot_preset_upstairs_mop": B("robot_preset_upstairs_mop", { preset_id: 3, preset_name: "Upstairs mop", map_id: 2, map_name: "Up" }),
      "button.robot_preset_landing": B("robot_preset_landing", { preset_id: 7, preset_name: "Landing", map_id: 2, map_name: "Up" }),
      "button.robot_preset_old": B("robot_preset_old", { preset_id: 8, preset_name: "Old" }),
    };
    const entities = {}; for (const id in states) entities[id] = { entity_id: id, device_id: "d", platform: "tapo_rv30" };
    for (const id in states) if (id.startsWith("button.")) entities[id].translation_key = "preset";
    window.ws = []; window.services = [];
    window.hass = { states, entities, devices: { d: { name: "Robot" } }, user: { is_admin: true },
      callService: async (d, s, data, target) => { window.services.push({ s, data }); },
      callWS: async (m) => { window.ws.push(m); throw { message: "unknown " + m.type }; },
      connection: { subscribeEvents: async () => () => {}, subscribeMessage: async () => () => {} } };
  });
  await page.addScriptTag({ content: fs.readFileSync(panelPath, "utf8") });
  const out = { picked: {}, sent: {} };
  const click = async (sel) => { await page.evaluate((sel) => window.p.shadowRoot.querySelector(sel).click(), sel); await page.waitForTimeout(150); };
  await page.evaluate(() => { const p = document.createElement("tapo-rv30-panel"); window.p = p; document.body.appendChild(p); p.narrow = false; p.hass = window.hass; });
  await page.waitForTimeout(200);
  out.tab = await page.evaluate(() => window.p._tab);
  for (const name of ["Landing", "Upstairs mop", "Old"]) {
    await click('.row[data-id="5"] [data-act="edit"]');
    out.selected = await page.evaluate(() => window.p.shadowRoot.querySelector("select.preset").selectedOptions[0].textContent);
    out.picked[name] = await page.evaluate((name) => { const sel = window.p.shadowRoot.querySelector("select.preset");
      sel.value = [...sel.options].find((o) => o.textContent === name).value; sel.dispatchEvent(new Event("change")); return sel.value; }, name);
    await click(".save");
    out.sent[name] = await page.evaluate(() => window.services.filter((x) => x.s === "set_schedule").map((x) => x.data).pop());
  }
  out.listCalls = await page.evaluate(() => window.ws.filter((m) => m.type === "tapo_rv30/preset/list").length);
  out.errors = errors;
  console.log(JSON.stringify(out));
  await browser.close();
})();
"""


@pytest.mark.skipif(not _has_playwright(), reason="playwright for node not installed")
def test_schedule_to_another_maps_preset_before_the_presets_tab():
    try:
        run = subprocess.run([NODE, "-e", SCHED_FALLBACK, str(PANEL)], capture_output=True, text=True, check=True, timeout=120)
    except subprocess.CalledProcessError as exc:
        if "Executable doesn't exist" in exc.stderr or "browserType.launch" in exc.stderr:
            pytest.skip("no browser for playwright")
        raise
    out = json.loads(run.stdout.strip().splitlines()[-1])
    assert out["errors"] == [] and out["tab"] == "schedules" and out["listCalls"] == 0
    assert out["selected"] == "Mop"                     # the schedule's own preset 3, not the upstairs one
    assert out["picked"] == {"Landing": "2:7", "Upstairs mop": "2:3", "Old": "8"}
    # The preset's own map, never the schedule's (map 1 has no preset 7: the integration would refuse).
    assert out["sent"]["Landing"] == {"preset": 7, "map": "2", "schedule_id": 5}
    assert out["sent"]["Upstairs mop"] == {"preset": 3, "map": "2", "schedule_id": 5}
    # A button that does not name its map: no map, so the integration looks on every map.
    assert out["sent"]["Old"] == {"preset": 8, "schedule_id": 5}
