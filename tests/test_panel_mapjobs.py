"""The sidebar page runs one map job (a backup or a copy) at a time. When the job ends on another
tab than the one that started it, the tab showing then lets go of the lock too: the buttons come
back, the Backups list picks up the new backup, and nothing the user has open is thrown away. Run
in a headless browser against the real file where Playwright for node is there."""
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

# Each scenario gets a fresh page. The robot's backup_map and copy_map calls wait until the script
# calls finish() (or fail()); a finished backup adds one to the list the panel reads.
SCRIPT = r"""
const { chromium } = require("playwright"), fs = require("fs");
const panelPath = process.argv[1];
(async () => {
  const browser = await chromium.launch(), out = {};
  const scenario = async (name, body) => {
    const page = await browser.newPage({ viewport: { width: 1100, height: 1400 } });
    const errors = []; page.on("pageerror", (e) => errors.push(e.message));
    await page.setContent(`<!doctype html><body style="margin:0"></body>`);
    await page.evaluate(() => {
      customElements.define("tapo-rv30-card", class extends HTMLElement { setConfig(c) { this._config = c; } set hass(h) {} });
      const S = (id, attrs = {}, state = "unknown") => ({ entity_id: id, state, attributes: attrs });
      const states = {
        "vacuum.robot": S("vacuum.robot", { friendly_name: "Robot", integration: "tapo_rv30" }, "docked"),
        "camera.robot_map": S("camera.robot_map", { map_id: 1, maps: [{ id: 1, name: "Down", current: true }, { id: 2, name: "Up", current: false }] }),
        "select.robot_mode": S("select.robot_mode", { friendly_name: "Robot Mode", options: ["a", "b"] }, "a"),
      };
      const entities = {}; for (const id in states) entities[id] = { entity_id: id, device_id: "d", platform: "tapo_rv30" };
      window.backups = [{ file: "cloud_1_1000.bin", source: "cloud", map_id: 1, map_name: "Down", size: 2048, when: "2026-10-01 10:00", thumb: null, facts: null }];
      window.svc = []; window.lists = 0;
      window.hass = { states, entities, devices: { d: { name: "Robot" } }, user: { is_admin: true },
        callService: (d, s) => { window.svc.push(s); return new Promise((res, rej) => {
          window.fail = () => rej({ message: "the robot is busy" });
          window.finish = () => {
            if (s === "backup_map") window.backups = [{ file: "cloud_1_2000.bin", source: "cloud", map_id: 1, map_name: "Down", size: 2048, when: "2026-10-26 18:00", thumb: null, facts: null }, ...window.backups];
            res({ response: { next_steps: s === "backup_map" ? "Backed up" : "Copied" } });
          };
        }); },
        callWS: async (m) => { if (m.type === "tapo_rv30/backups/list") { window.lists++; return { folder: "x", backups: window.backups }; } return {}; },
        connection: { subscribeEvents: async () => () => {}, subscribeMessage: async () => () => {} } };
    });
    await page.addScriptTag({ content: fs.readFileSync(panelPath, "utf8") });
    await page.evaluate(() => { const p = document.createElement("tapo-rv30-panel"); window.p = p; document.body.appendChild(p); p.narrow = false; p.hass = window.hass; });
    await page.waitForTimeout(200);
    const ev = (f, a) => page.evaluate(f, a);
    const settle = () => page.waitForTimeout(250);
    const click = async (sel) => { await ev((sel) => window.p.shadowRoot.querySelector(sel).click(), sel); await settle(); };
    const tab = (t) => click(`.tabs [data-tab="${t}"]`);
    const update = async () => { for (let i = 0; i < 2; i++) { await ev(() => { window.p.hass = { ...window.hass }; }); await page.waitForTimeout(80); } };
    const backups = () => ev(() => { const r = window.p.shadowRoot, b = r.querySelector(".bknow");
      return { busy: window.p._mapJobBusy, disabled: b.disabled, pick: r.querySelector(".bkmap").disabled, title: b.title,
        cards: [...r.querySelectorAll(".bkcard .meta > .s")].map((e) => e.textContent), lists: window.lists }; });
    const settings = () => ev(() => ({ busy: window.p._mapJobBusy,
      btns: [...window.p.shadowRoot.querySelectorAll("[data-backup], [data-copy]")].map((b) => [b.dataset.backup ? "backup" : "copy", b.disabled, b.title]) }));
    const r = { };
    await body({ ev, settle, click, tab, update, backups, settings, r });
    r.errors = errors; r.svc = await ev(() => window.svc);
    out[name] = r;
    await page.close();
  };

  // Started on Backups, away to Settings and back, finished there.
  await scenario("backups_back", async ({ ev, click, tab, update, backups, settle, r }) => {
    await tab("backups"); await click(".bknow");
    r.during = await backups();
    await tab("settings"); await tab("backups");
    r.again = await backups();
    await ev(() => window.finish()); await settle(); await update();
    r.after = await backups();
  });
  // Started on Backups, finished while Settings shows, then back to Backups.
  await scenario("finished_on_settings", async ({ ev, click, tab, update, backups, settings, settle, r }) => {
    await tab("backups"); await click(".bknow");
    await tab("settings");
    r.during = await settings();
    await ev(() => window.finish()); await settle(); await update();
    r.after = await settings();
    await tab("backups");
    r.backups = await backups();
  });
  // Started from a map row on Settings, watched from Backups.
  await scenario("settings_from_backups", async ({ ev, click, tab, update, backups, settle, r }) => {
    await tab("settings"); await click('[data-backup="2"]');
    await tab("backups");
    r.during = await backups();
    await ev(() => window.finish()); await settle(); await update();
    r.after = await backups();
  });
  // A restore box open on Backups when the job ends: left alone, buttons still come back.
  await scenario("restore_box", async ({ ev, click, tab, update, backups, settle, r }) => {
    await tab("settings"); await click('[data-backup="2"]');
    await tab("backups"); await click(".bkrestore");
    await ev(() => window.p.shadowRoot.querySelector(".restore-opts").dataset.mark = "1");
    r.during = await backups();
    await ev(() => window.finish()); await settle(); await update();
    r.after = await backups();
    r.box = await ev(() => { const b = window.p.shadowRoot.querySelector(".restore-opts"); return !!b && b.isConnected && b.dataset.mark === "1"; });
  });
  // A setting being changed on Settings when the job ends: not redrawn under the user, but redrawn
  // (with the buttons back) once focus leaves it.
  await scenario("settings_form_open", async ({ ev, click, tab, update, settings, settle, r }) => {
    await tab("backups"); await click(".bknow");
    await tab("settings");
    await ev(() => { const s = window.p.shadowRoot.querySelector("[data-sel]"); s.dataset.mark = "1"; s.focus(); });
    await ev(() => window.finish()); await settle(); await update();
    r.held = await settings();
    r.kept = await ev(() => { const s = window.p.shadowRoot.querySelector("[data-sel]"); return s.dataset.mark === "1" && window.p.shadowRoot.activeElement === s; });
    await ev(() => window.p.shadowRoot.querySelector("[data-sel]").blur()); await settle();
    r.after = await settings();
  });
  // A copy that works: the pane is redrawn and every button is back.
  await scenario("copy_ok", async ({ ev, click, tab, settings, settle, r }) => {
    await tab("settings"); await click('[data-copy="1"]'); await click('.maprow [data-act="save"]');
    r.during = await settings();
    await ev(() => window.finish()); await settle();
    r.after = await settings();
    r.rowsOpen = await ev(() => window.p.shadowRoot.querySelectorAll(".maprow input.rename, .maprow [data-act]").length);
  });
  // A copy started on Settings, finished while Backups shows.
  await scenario("copy_from_backups", async ({ ev, click, tab, update, backups, settle, r }) => {
    await tab("settings"); await click('[data-copy="1"]'); await click('.maprow [data-act="save"]');
    await tab("backups");
    r.during = await backups();
    await ev(() => window.finish()); await settle(); await update();
    r.after = await backups();
  });
  // A copy the robot refuses: the row stays open to try again; the rest follows once it is closed.
  await scenario("copy_fail", async ({ ev, click, tab, settings, settle, r }) => {
    await tab("settings"); await click('[data-copy="1"]'); await click('.maprow [data-act="save"]');
    await ev(() => window.fail()); await settle();
    r.row = await ev(() => { const root = window.p.shadowRoot, i = root.querySelector(".maprow input.rename");
      return { open: !!i, enabled: !!i && !i.disabled, focused: root.activeElement === i, save: !root.querySelector('.maprow [data-act="save"]').disabled }; });
    r.busy = await ev(() => window.p._mapJobBusy);
    await click('.maprow [data-act="cancel"]');
    r.after = await settings();
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


NEW, OLD = "2026-10-26 18:00 \u00b7 2 KB", "2026-10-01 10:00 \u00b7 2 KB"
BUSY = "A backup or copy is running"


def _free(b):
    return b["busy"] is False and b["disabled"] is False and b["pick"] is False and b["title"] == "" and b["cards"] == [NEW, OLD]


def test_backup_from_backups_finished_after_coming_back(out):
    r = out["backups_back"]
    assert r["during"]["disabled"] is True and r["during"]["busy"] is True
    assert r["again"]["disabled"] is True and r["again"]["title"] == BUSY
    assert _free(r["after"]), r["after"]
    assert r["after"]["lists"] == r["again"]["lists"] + 1        # read again once, not on every update
    assert r["svc"] == ["backup_map"]


def test_backup_from_backups_finished_on_settings(out):
    r = out["finished_on_settings"]
    assert r["during"]["busy"] is True and all(d for _, d, _ in r["during"]["btns"])
    assert r["after"]["busy"] is False
    assert [(k, d) for k, d, _ in r["after"]["btns"]] == [("backup", False), ("copy", False)] * 2
    assert BUSY not in [t for _, _, t in r["after"]["btns"]]
    assert _free(r["backups"]), r["backups"]


def test_backup_from_settings_watched_from_backups(out):
    r = out["settings_from_backups"]
    assert r["during"]["disabled"] is True and r["during"]["cards"] == [OLD]
    assert _free(r["after"]), r["after"]


def test_open_restore_box_is_not_wiped(out):
    r = out["restore_box"]
    assert r["box"] is True
    assert r["after"]["disabled"] is False and r["after"]["title"] == "" and r["after"]["busy"] is False
    assert r["after"]["lists"] == r["during"]["lists"]          # the list under the box is left as it is


def test_open_setting_held_until_focus_leaves(out):
    r = out["settings_form_open"]
    assert r["kept"] is True and r["held"]["busy"] is False
    assert all(d for _, d, _ in r["held"]["btns"])               # not redrawn under the user yet
    assert [(k, d) for k, d, _ in r["after"]["btns"]] == [("backup", False), ("copy", False)] * 2


def test_copy_done_on_settings(out):
    r = out["copy_ok"]
    assert all(d for _, d, _ in r["during"]["btns"])
    assert r["rowsOpen"] == 0
    assert [(k, d) for k, d, _ in r["after"]["btns"]] == [("backup", False), ("copy", False)] * 2
    assert r["svc"] == ["copy_map"]


def test_copy_done_while_on_backups(out):
    r = out["copy_from_backups"]
    assert r["during"]["disabled"] is True
    after = r["after"]
    assert after["busy"] is False and after["disabled"] is False and after["title"] == ""
    assert after["lists"] == r["during"]["lists"] + 1


def test_copy_refused_keeps_the_row(out):
    r = out["copy_fail"]
    assert r["row"] == {"open": True, "enabled": True, "focused": True, "save": True}
    assert r["busy"] is False
    assert [(k, d) for k, d, _ in r["after"]["btns"]] == [("backup", False), ("copy", False)] * 2
