"""The map editor's per-room cleaning direction: a Default / Horizontal / Vertical choice per room
where the robot has one, labelled as the map is shown (turned a quarter, horizontal and vertical
swap), and Save sends only the rooms changed, as the robot's floor_texture. Stripes are drawn along
each room's direction. The choice runs in a headless browser where Playwright for node is there;
the stripes under node with the DOM stubbed."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

PANEL = Path(__file__).resolve().parent.parent / "custom_components" / "tapo_rv30" / "frontend" / "tapo-rv30-panel.js"
NODE = shutil.which("node")


def _has_playwright() -> bool:
    if not NODE:
        return False
    try:
        subprocess.run([NODE, "-e", "require('playwright')"], check=True, capture_output=True, timeout=30)
        return True
    except (subprocess.SubprocessError, OSError):
        return False


needs_node = pytest.mark.skipif(not NODE, reason="node not installed")
needs_browser = pytest.mark.skipif(not _has_playwright(), reason="playwright for node not installed")

# One made-up robot with one map of two rooms: Hall (robot's own pattern) and Den (90).
BROWSER = r"""
const { chromium } = require("playwright"), fs = require("fs");
const panelPath = process.argv[1];
(async () => {
  const browser = await chromium.launch(), out = {};
  const scenario = async (name, opts, body) => {
    const page = await browser.newPage({ viewport: { width: 1100, height: 1400 } });
    const errors = []; page.on("pageerror", (e) => errors.push(e.message));
    await page.setContent(`<!doctype html><body style="margin:0"></body>`);
    await page.evaluate((opts) => {
      const c = document.createElement("canvas"); c.width = 200; c.height = 200;
      const g = c.getContext("2d"); g.fillStyle = "#ddd"; g.fillRect(0, 0, 200, 200);
      const pic = c.toDataURL("image/png");
      // The room-id grid: 50 x 50 cells, Hall (1) on the left, Den (2) on the right.
      const m = document.createElement("canvas"); m.width = 50; m.height = 50;
      const mg = m.getContext("2d"); mg.fillStyle = "rgb(1,1,1)"; mg.fillRect(0, 0, 25, 50); mg.fillStyle = "rgb(2,2,2)"; mg.fillRect(25, 0, 25, 50);
      const mask = m.toDataURL("image/png");
      customElements.define("tapo-rv30-card", class extends HTMLElement { setConfig(c) { this._config = c; } set hass(h) {} });
      const S = (id, attrs = {}, state = "unknown") => ({ entity_id: id, state, attributes: attrs });
      const states = {
        "vacuum.alpha": S("vacuum.alpha", { friendly_name: "Alpha", integration: "tapo_rv30" }, "docked"),
        "camera.alpha_map": S("camera.alpha_map", { map_id: 1, maps: [{ id: 1, name: "Ground", current: true }] }),
      };
      const entities = {};
      for (const id in states) entities[id] = { entity_id: id, device_id: "da", platform: "tapo_rv30" };
      window.rooms = [{ id: 1, name: "Hall", floor_texture: -1 }, { id: 2, name: "Den", floor_texture: 90 }];
      window.applies = [];
      window.hass = { states, entities, devices: { da: { name: "Alpha" } }, user: { is_admin: true },
        callService: () => Promise.resolve(),
        callWS: (msg) => {
          if (msg.type === "tapo_rv30/map/edit_get") return Promise.resolve({ map_id: 1, current: true, picture: pic, room_mask: mask,
            geometry: { scale_px_per_cell: 4, resolution_mm: 50, real_origin_mm: [0, 0], grid_size: [50, 50], image_size: [200, 200], rotation: opts.rotation },
            areas: { forbid: [], virtual_wall: [] }, furniture: [], rooms: JSON.parse(JSON.stringify(window.rooms)), clean_direction: opts.supported });
          if (msg.type === "tapo_rv30/map/edit_apply") {
            window.applies.push(JSON.parse(JSON.stringify(msg)));
            if (opts.refuse && msg.rooms) return Promise.resolve({ map_id: 1, result: { forbid: 0, rooms: -1001 } });
            for (const r of msg.rooms || []) window.rooms.find((x) => x.id === r.id).floor_texture = r.floor_texture;
            return Promise.resolve({ result: {} });
          }
          return Promise.resolve({});
        },
        connection: { subscribeEvents: async () => () => {}, subscribeMessage: async () => () => {} } };
    }, opts);
    await page.addScriptTag({ content: fs.readFileSync(panelPath, "utf8") });
    await page.evaluate(() => { const p = document.createElement("tapo-rv30-panel"); window.p = p; document.body.appendChild(p); p.narrow = false; p.hass = window.hass; });
    await page.waitForTimeout(200);
    const ev = (f, a) => page.evaluate(f, a);
    const settle = () => page.waitForTimeout(250);
    const click = async (sel) => { await ev((sel) => window.p.shadowRoot.querySelector(sel).click(), sel); await settle(); };
    const pick = async (i, value) => { await ev(([i, v]) => { const s = window.p.shadowRoot.querySelectorAll(".edir")[i]; s.value = v; s.dispatchEvent(new Event("change")); }, [i, value]); await settle(); };
    const editor = () => ev(() => { const p = window.p, r = p.shadowRoot;
      return { shown: [...r.querySelectorAll(".edir")].map((s) => s.value), undo: p._edit.undo.length,
        heading: (r.querySelector(".erooms h5") || {}).textContent || "", status: r.querySelector(".estatus").textContent,
        stripes: !!p._edit.mask, applies: window.applies }; });
    const r = {};
    await click('.tabs [data-tab="edit"]');
    await body({ ev, settle, click, pick, editor, r });
    r.errors = errors;
    out[name] = r;
    await page.close();
  };

  for (const rotation of [0, 90, 180, 270]) {
    await scenario(`turn${rotation}`, { rotation, supported: true }, async ({ ev, click, pick, editor, r }) => {
      r.loaded = await editor();
      await pick(0, "horizontal");
      r.changed = await editor();
      await click(".eundo");
      r.undone = await editor();
      await pick(0, "horizontal"); await pick(1, "default");
      await click(".esave");
      r.saved = await editor();
      await click(".esave");                                   // nothing changed since: no rooms sent
      r.again = await editor();
    });
  }
  await scenario("refused", { rotation: 0, supported: true, refuse: true }, async ({ click, pick, editor, r }) => {
    await pick(0, "vertical");
    await click(".esave");
    r.saved = await editor();
  });
  await scenario("unsupported", { rotation: 0, supported: false }, async ({ click, editor, r }) => {
    r.loaded = await editor();
    await click(".esave");
    r.saved = await editor();
  });
  console.log(JSON.stringify(out));
  await browser.close();
})();
"""


@pytest.fixture(scope="module")
def out():
    if not NODE or not _has_playwright():
        pytest.skip("playwright for node not installed")
    try:
        run = subprocess.run([NODE, "-e", BROWSER, str(PANEL)], capture_output=True, text=True, check=True, timeout=180)
    except subprocess.CalledProcessError as exc:
        if "Executable doesn't exist" in exc.stderr or "browserType.launch" in exc.stderr:
            pytest.skip("no browser for playwright")
        raise
    res = json.loads(run.stdout.strip().splitlines()[-1])
    for name, r in res.items():
        assert r["errors"] == [], name
    return res


@needs_browser
@pytest.mark.parametrize("rotation", [0, 90, 180, 270])
def test_direction_choice_follows_the_map_as_shown(out, rotation):
    r = out[f"turn{rotation}"]
    quarter = rotation in (90, 270)
    # Den is 90 on the robot: vertical on the map as drawn, horizontal once turned a quarter.
    assert r["loaded"]["shown"] == ["default", "horizontal" if quarter else "vertical"]
    assert "cleaning direction" in r["loaded"]["heading"] and r["loaded"]["stripes"] is True
    assert r["changed"]["shown"][0] == "horizontal" and r["changed"]["undo"] == 1     # unsaved edit
    assert r["undone"]["shown"][0] == "default" and r["undone"]["undo"] == 0
    # Only the rooms changed are sent, in the robot's frame: horizontal as shown is 0 unturned, 90 turned.
    (sent,) = r["saved"]["applies"]
    assert sent["rooms"] == [{"id": 1, "floor_texture": 90 if quarter else 0}, {"id": 2, "floor_texture": -1}]
    assert sent["areas"] == {"forbid": [], "virtual_wall": []} and sent["furniture"] == []      # the same save
    assert r["saved"]["status"] == "Saved." and r["saved"]["shown"] == ["horizontal", "default"]
    assert "rooms" not in r["again"]["applies"][1]


@needs_browser
def test_a_refused_room_write_is_not_reported_as_saved(out):
    r = out["refused"]
    assert r["saved"]["applies"][0]["rooms"] == [{"id": 1, "floor_texture": 90}]
    assert r["saved"]["status"] == "Saved, but the robot refused the cleaning direction change (error -1001)."
    assert r["saved"]["shown"] == ["default", "vertical"]          # the robot's own value, reloaded


@needs_browser
def test_no_direction_choice_without_the_robot_support(out):
    r = out["unsupported"]
    assert r["loaded"]["shown"] == [] and "cleaning direction" not in r["loaded"]["heading"]
    assert "rooms" not in r["saved"]["applies"][0]


# The stripes: under node with a stub canvas that records each fillRect.
STRIPES = r"""
const vm = require("vm"), fs = require("fs");
const mk = () => ({ classList: { toggle() {}, add() {} }, style: {}, dataset: {}, querySelector: () => mk(), querySelectorAll: () => [] });
const defs = {};
const ctx = { console, Math, JSON, Number, String, Set, Map, Object, Array, Promise, Date, Int16Array, Uint8Array,
  HTMLElement: class { attachShadow() { this.shadowRoot = mk(); return this.shadowRoot; } },
  customElements: { get: (n) => defs[n], define: (n, c) => { defs[n] = c; } }, CustomEvent: class {}, document: { createElement: mk } };
ctx.window = ctx;
vm.createContext(ctx);
const Panel = vm.runInContext(fs.readFileSync(process.argv[1], "utf8") + `;customElements.get("tapo-rv30-panel")`, ctx);
const p = Object.create(Panel.prototype);
// 12 x 12 cells: room 1 the left half, room 2 the right half; 4 px per cell.
const w = 12, h = 12, ids = new Uint8Array(w * h);
for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) ids[y * w + x] = x < 6 ? 1 : 2;
const run = (rotation, rooms) => {
  const rects = [];
  p._edit = { dirOk: true, mask: { w, h, ids }, geom: { rotation }, rooms };
  p._editStripes({ canvas: { width: 48 }, fillRect: (...a) => rects.push(a) });
  return rects.map((a) => a.map((v) => Math.round(v * 100) / 100));
};
console.log(JSON.stringify({
  flat0: run(0, [{ id: 1, floor_texture: 0 }, { id: 2, floor_texture: -1 }]),
  upright0: run(0, [{ id: 1, floor_texture: 90 }, { id: 2, floor_texture: null }]),
  flat90: run(90, [{ id: 2, floor_texture: 90 }]),
  none: run(0, [{ id: 1, floor_texture: -1 }, { id: 2, floor_texture: 7 }]),
  unsupported: (() => { const rects = []; p._edit = { dirOk: false, mask: { w, h, ids }, geom: { rotation: 0 }, rooms: [{ id: 1, floor_texture: 0 }] };
    p._editStripes({ canvas: { width: 48 }, fillRect: (...a) => rects.push(a) }); return rects.length; })(),
}));
"""


@needs_node
def test_stripes_run_along_each_rooms_direction_inside_the_room():
    run = subprocess.run([NODE, "-e", STRIPES, str(PANEL)], capture_output=True, text=True, check=True, timeout=60)
    got = json.loads(run.stdout.strip().splitlines()[-1])
    # 0 unturned: across the picture, in Hall only (x 0 to 24 px), on cell rows 3 and 9.
    assert got["flat0"] == [[0, 13.25, 24, 1.5], [0, 37.25, 24, 1.5]]
    # 90 unturned: down the picture, in Hall only, on cell columns 3 (and not 9, which is Den).
    assert got["upright0"] == [[13.25, 0, 1.5, 48]]
    # 90 turned a quarter: across as shown, in Den only (x 24 to 48 px).
    assert got["flat90"] == [[24, 13.25, 24, 1.5], [24, 37.25, 24, 1.5]]
    assert got["none"] == [] and got["unsupported"] == 0
