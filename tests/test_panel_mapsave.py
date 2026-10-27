"""The sidebar page's map editor while a save is with the robot: nothing can be drawn, undone,
turned, discarded or saved again until the reload after it is in; an editor opened for the same
robot meanwhile waits for the save instead of reading the zones from before it; a late reply for
one robot never reloads (and wipes) the editor of another; and a Save cannot race a Turn. Run in a
headless browser against the real file where Playwright for node is there."""
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


pytestmark = [pytest.mark.skipif(not NODE, reason="node not installed"),
              pytest.mark.skipif(not _has_playwright(), reason="playwright for node not installed")]

# Two made-up robots: Alpha with two maps, Beta with one. edit_apply waits until the script calls
# finish() (or fail()); a finished save becomes what edit_get returns for that robot from then on.
# set_map_rotation waits for turned(). Map pictures come over a routed URL, held back for slow ms.
SCRIPT = r"""
const { chromium } = require("playwright"), fs = require("fs");
const panelPath = process.argv[1];
(async () => {
  const browser = await chromium.launch(), out = {};
  const scenario = async (name, body) => {
    const page = await browser.newPage({ viewport: { width: 1100, height: 1400 } });
    const errors = []; page.on("pageerror", (e) => errors.push(e.message));
    await page.setContent(`<!doctype html><body style="margin:0"></body>`);
    const png = Buffer.from((await page.evaluate(() => { const c = document.createElement("canvas"); c.width = 200; c.height = 200;
      const g = c.getContext("2d"); g.fillStyle = "#ddd"; g.fillRect(0, 0, 200, 200); return c.toDataURL("image/png"); })).split(",")[1], "base64");
    const pics = { slow: 0 };
    await page.route("http://pic.test/**", async (route) => {
      if (pics.slow) await new Promise((ok) => setTimeout(ok, pics.slow));
      await route.fulfill({ status: 200, contentType: "image/png", body: png });
    });
    await page.evaluate(() => {
      customElements.define("tapo-rv30-card", class extends HTMLElement { setConfig(c) { this._config = c; } set hass(h) {} });
      const S = (id, attrs = {}, state = "unknown") => ({ entity_id: id, state, attributes: attrs });
      const states = {
        "vacuum.alpha": S("vacuum.alpha", { friendly_name: "Alpha", integration: "tapo_rv30" }, "docked"),
        "camera.alpha_map": S("camera.alpha_map", { map_id: 1, maps: [{ id: 1, name: "Ground", current: true }, { id: 2, name: "Cellar", current: false }] }),
        "vacuum.beta": S("vacuum.beta", { friendly_name: "Beta", integration: "tapo_rv30" }, "docked"),
        "camera.beta_map": S("camera.beta_map", { map_id: 7, maps: [{ id: 7, name: "Loft", current: true }] }),
      };
      const entities = {};
      for (const id in states) entities[id] = { entity_id: id, device_id: id.includes("alpha") ? "da" : "db", platform: "tapo_rv30" };
      window.store = { "vacuum.alpha": { forbid: [] }, "vacuum.beta": { forbid: [] } };
      window.ws = []; window.svc = []; let n = 0;
      window.hass = { states, entities, devices: { da: { name: "Alpha" }, db: { name: "Beta" } }, user: { is_admin: true },
        callService: (d, s) => { window.svc.push(s); return new Promise((ok) => { window.turned = ok; }); },
        callWS: (m) => {
          window.ws.push({ type: m.type, entity_id: m.entity_id, wait: m.wait });
          if (m.type === "tapo_rv30/map/edit_get" && window.busyGets > 0) {
            window.busyGets--; return Promise.reject({ code: "busy", message: "A map write to Alpha is still running" });
          }
          if (m.type === "tapo_rv30/map/edit_get") return Promise.resolve({ map_id: m.map_id, current: true, picture: `http://pic.test/map.png?n=${++n}`,
            geometry: { scale_px_per_cell: 4, resolution_mm: 50, real_origin_mm: [0, 0], grid_size: [50, 50], image_size: [200, 200], rotation: 0 },
            areas: JSON.parse(JSON.stringify(window.store[m.entity_id])), furniture: [], rooms: [] });
          if (m.type === "tapo_rv30/map/edit_apply") return new Promise((ok, no) => {
            window.finish = () => { window.store[m.entity_id] = JSON.parse(JSON.stringify(m.areas)); ok({ result: {} }); };
            window.fail = () => no({ message: "the robot is busy" });
          });
          return Promise.resolve({});
        },
        connection: { subscribeEvents: async () => () => {}, subscribeMessage: async () => () => {} } };
    });
    await page.addScriptTag({ content: fs.readFileSync(panelPath, "utf8") });
    await page.evaluate(() => { const p = document.createElement("tapo-rv30-panel"); window.p = p; document.body.appendChild(p); p.narrow = false; p.hass = window.hass; });
    await page.waitForTimeout(200);
    const ev = (f, a) => page.evaluate(f, a);
    const settle = () => page.waitForTimeout(250);
    const click = async (sel) => { await ev((sel) => window.p.shadowRoot.querySelector(sel).click(), sel); await settle(); };
    const tab = (t) => click(`.tabs [data-tab="${t}"]`);
    const robot = (id) => click(`.robots button[data-id="${id}"]`);
    // A no-go zone dragged across the canvas, from and to fractions of its size.
    const zone = async (x0, y0, x1, y1) => {
      await click('.etool[data-tool="forbid"]');
      const b = await ev(() => { const r = window.p.shadowRoot.querySelector(".ecanvas").getBoundingClientRect(); return { x: r.left, y: r.top, w: r.width, h: r.height }; });
      await page.mouse.move(b.x + b.w * x0, b.y + b.h * y0); await page.mouse.down();
      await page.mouse.move(b.x + b.w * x1, b.y + b.h * y1, { steps: 4 }); await page.mouse.up(); await settle();
    };
    const editor = () => ev(() => { const p = window.p, r = p.shadowRoot, e = p._edit;
      return { robot: e.robot, zones: e.areas ? (e.areas.forbid || []).length : null, undo: e.undo.length, status: r.querySelector(".estatus").textContent,
        save: r.querySelector(".esave").disabled, picker: r.querySelector(".emap").value, pickerOff: r.querySelector(".emap").disabled,
        turnOff: [...r.querySelectorAll(".eturn")].every((b) => b.disabled),
        gets: window.ws.filter((m) => m.type === "tapo_rv30/map/edit_get").map((m) => m.entity_id),
        waits: window.ws.filter((m) => m.type === "tapo_rv30/map/edit_get").map((m) => m.wait === true),
        applies: window.ws.filter((m) => m.type === "tapo_rv30/map/edit_apply").length, svc: window.svc }; });
    const r = {};
    await body({ ev, settle, click, tab, robot, zone, editor, pics, page, r });
    r.errors = errors;
    out[name] = r;
    await page.close();
  };

  // Drawn and saved; then more drawn, undone, discarded, turned and another map picked while the
  // robot is saving; then drawn again while the reload's picture is still coming in.
  await scenario("during_save", async ({ ev, settle, click, zone, editor, pics, page, r }) => {
    await click('.tabs [data-tab="edit"]');
    await zone(0.1, 0.1, 0.3, 0.3);
    r.before = await editor();
    await click(".esave");
    r.saving = await editor();
    await zone(0.5, 0.5, 0.8, 0.8);
    await click(".eundo"); await click(".ecancel"); await click(".eturn");
    await ev(() => { const s = window.p.shadowRoot.querySelector(".emap"); s.value = "2"; s.dispatchEvent(new Event("change")); }); await settle();
    r.tried = await editor();
    pics.slow = 1500;
    await ev(() => window.finish()); await settle();
    await zone(0.5, 0.5, 0.8, 0.8);
    r.reloading = await editor();
    await page.waitForTimeout(1500);
    r.after = await editor();
    pics.slow = 0;
    await zone(0.5, 0.5, 0.8, 0.8);
    r.again = await editor();
  });
  // Saved on Alpha, away to another tab and back to Edit before the reply.
  await scenario("same_robot_tab", async ({ ev, settle, tab, zone, editor, click, r }) => {
    await tab("edit");
    await zone(0.1, 0.1, 0.3, 0.3);
    await click(".esave");
    await tab("schedules"); await tab("edit");
    await zone(0.5, 0.5, 0.8, 0.8);
    r.waiting = await editor();
    await ev(() => window.finish()); await settle();
    r.after = await editor();
  });
  // Saved on Alpha, over to Beta and back to Alpha before the reply.
  await scenario("robot_round_trip", async ({ ev, settle, tab, robot, zone, editor, click, r }) => {
    await tab("edit");
    await zone(0.1, 0.1, 0.3, 0.3);
    await click(".esave");
    await robot("vacuum.beta"); await robot("vacuum.alpha");
    r.waiting = await editor();
    await ev(() => window.finish()); await settle();
    r.after = await editor();
  });
  // Saved on Alpha, then over to Beta and drawn there before Alpha's reply comes in.
  await scenario("switch_robot", async ({ ev, settle, tab, robot, zone, editor, click, r }) => {
    await tab("edit");
    await zone(0.1, 0.1, 0.3, 0.3);
    await click(".esave");
    await robot("vacuum.beta");
    await zone(0.5, 0.5, 0.8, 0.8);
    r.before = await editor();
    await ev(() => window.finish()); await settle();
    r.after = await editor();
    r.store = await ev(() => window.store);
  });
  // A failed save on Alpha reported after moving to Beta: Beta's editor is left as it is, and the
  // failure is shown on going back to Alpha.
  await scenario("switch_robot_fail", async ({ ev, settle, tab, robot, zone, editor, click, r }) => {
    await tab("edit");
    await zone(0.1, 0.1, 0.3, 0.3);
    await click(".esave");
    await robot("vacuum.beta");
    await zone(0.5, 0.5, 0.8, 0.8);
    r.before = await editor();
    await ev(() => window.fail()); await settle();
    r.after = await editor();
    await robot("vacuum.alpha");
    r.back = await editor();
    await robot("vacuum.beta"); await robot("vacuum.alpha");
    r.again = await editor();
  });
  // Save pressed (or called) while a turn is with the robot: refused until the turn is in.
  await scenario("turn_then_save", async ({ ev, settle, tab, zone, editor, click, r }) => {
    await tab("edit");
    await zone(0.1, 0.1, 0.3, 0.3);
    await click(".eturn");
    await click(".esave"); await ev(() => { window.p._editSave(); }); await settle();
    r.turning = await editor();
    await ev(() => window.turned(true)); await settle();
    r.after = await editor();
  });
  // The editor opened while a map write holds the robot past the backend's wait: asked once more;
  // still busy, it says so and Discard tries again.
  await scenario("busy_load", async ({ ev, settle, tab, editor, click, r }) => {
    await ev(() => { window.busyGets = 1; });
    await tab("edit");
    r.retried = await editor();
    await tab("schedules");
    await ev(() => { window.busyGets = 2; });
    await tab("edit");
    r.busy = await editor();
    await click(".ecancel");
    r.again = await editor();
  });
  console.log(JSON.stringify(out));
  await browser.close();
})();
"""


@pytest.fixture(scope="module")
def out():
    try:
        run = subprocess.run([NODE, "-e", SCRIPT, str(PANEL)], capture_output=True, text=True, check=True, timeout=180)
    except subprocess.CalledProcessError as exc:
        if "Executable doesn't exist" in exc.stderr or "browserType.launch" in exc.stderr:
            pytest.skip("no browser for playwright")
        raise
    res = json.loads(run.stdout.strip().splitlines()[-1])
    for name, r in res.items():
        assert r["errors"] == [], name
    return res


def _held(e):
    return e["save"] is True and e["pickerOff"] is True and e["turnOff"] is True


def test_no_edits_while_saving(out):
    r = out["during_save"]
    assert r["before"]["zones"] == 1 and r["before"]["undo"] == 1 and r["before"]["save"] is False
    assert _held(r["saving"]) and r["saving"]["status"] == "Saving to robot..."
    # The second zone, the undo, Discard, Turn and the other map are all refused, not quietly lost
    # when the save reloads the map.
    t = r["tried"]
    assert t["zones"] == 1 and t["undo"] == 1 and _held(t) and t["status"] == "Saving to robot..."
    assert t["picker"] == "1" and t["gets"] == ["vacuum.alpha"] and t["svc"] == []
    # Still held while the reload's picture comes in.
    assert r["reloading"]["zones"] == 1 and r["reloading"]["undo"] == 1 and _held(r["reloading"])
    a = r["after"]
    assert a["zones"] == 1 and a["undo"] == 0 and a["status"] == "Saved." and a["save"] is False and a["pickerOff"] is False
    assert r["again"]["zones"] == 2 and r["again"]["undo"] == 1      # drawing works again


def test_same_robot_editor_waits_for_the_save(out):
    for name in ("same_robot_tab", "robot_round_trip"):
        r = out[name]
        w = r["waiting"]
        # Not read from the robot (it would give the zones from before the save), nothing drawn, no Save.
        assert w["robot"] == "vacuum.alpha" and w["zones"] is None and _held(w), name
        assert w["status"] == "Saving to robot..." and w["gets"].count("vacuum.alpha") == 1, name
        a = r["after"]
        assert a["zones"] == 1 and a["undo"] == 0 and a["status"] == "Saved." and a["save"] is False, name
        assert a["gets"].count("vacuum.alpha") == 2 and a["applies"] == 1, name


def test_late_save_reply_leaves_the_other_robot_alone(out):
    r = out["switch_robot"]
    assert r["before"]["robot"] == "vacuum.beta" and r["before"]["zones"] == 1 and r["before"]["undo"] == 1
    assert r["before"]["save"] is False
    assert r["after"] == r["before"]                    # not reloaded, edit kept, no "Saved."
    assert r["store"]["vacuum.alpha"]["forbid"] and r["store"]["vacuum.beta"] == {"forbid": []}


def test_late_save_failure_told_on_return(out):
    r = out["switch_robot_fail"]
    assert r["before"]["robot"] == "vacuum.beta" and r["before"]["zones"] == 1
    assert r["after"] == r["before"]
    back = r["back"]
    assert back["robot"] == "vacuum.alpha" and back["zones"] == 0 and back["status"] == "Save failed: the robot is busy"
    assert back["save"] is False
    assert r["again"]["status"] == ""                     # told once


def test_save_refused_while_turning(out):
    r = out["turn_then_save"]
    t = r["turning"]
    assert t["svc"] == ["set_map_rotation"] and t["applies"] == 0 and _held(t) and t["status"] == "Turning the map..."
    a = r["after"]
    assert a["save"] is False and a["pickerOff"] is False and a["zones"] == 1 and a["applies"] == 0


def test_editor_load_waits_and_retries_once_when_busy(out):
    r = out["busy_load"]
    t = r["retried"]
    assert t["gets"] == ["vacuum.alpha", "vacuum.alpha"] and all(t["waits"]) and t["zones"] == 0 and t["status"] == ""
    b = r["busy"]
    assert b["gets"].count("vacuum.alpha") == 4 and b["status"] == "The robot's map is still being written; press Discard to try again."
    a = r["again"]
    assert a["gets"].count("vacuum.alpha") == 5 and a["zones"] == 0 and a["status"] == ""
