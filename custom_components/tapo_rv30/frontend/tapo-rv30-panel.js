/* Tapo Robot Vacuum sidebar page.
 *
 * One page per Home Assistant with everything the integration knows: the live map card,
 * a schedules editor (the robot's own schedules, through the integration's services),
 * history and statistics from the robot's clean records, per-room freshness, maintenance
 * and settings. Plain JavaScript, no build step, same visual language as the card.
 * Registered by the integration (toggle it in the integration's options).
 */
const DOMAIN = "tapo_rv30";
const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const FAN = ["Quiet", "Standard", "Turbo", "Max", "Ultra"];
const WATER = ["off", "low", "medium", "high"];
const START = { 0: "button", 1: "app", 2: "Alexa", 3: "Google", 4: "schedule", 5: "automation", 6: "IFTTT", 7: "Alice" };
// Minutes after midnight inside the robot's Do Not Disturb window? Windows cross midnight.
const toMin = (hhmm) => { const [h, m] = String(hhmm || "0:0").split(":").map(Number); return h * 60 + m; };
const inDnd = (dnd, hhmm) => {
  if (!dnd || !dnd.enabled) return false;
  const t = toMin(hhmm), a = toMin(dnd.start), b = toMin(dnd.end);
  if (a === b) return true;
  return a < b ? (t >= a && t < b) : (t >= a || t < b);
};
const dndText = (dnd) => `Do Not Disturb (${dnd.start} to ${dnd.end})`;
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const ago = (ts) => {
  if (!ts) return "never";
  const d = (Date.now() / 1000 - ts) / 86400;
  if (d < 1) return "today"; if (d < 2) return "yesterday"; if (d < 30) return `${Math.floor(d)} days ago`;
  return `${Math.floor(d / 30)} months ago`;
};

const STYLE = `
:host { display: block; height: 100%; background: var(--primary-background-color); color: var(--primary-text-color); }
.bar { display: flex; align-items: center; gap: 8px; height: 56px; padding: 0 12px; background: var(--app-header-background-color, var(--primary-color)); color: var(--app-header-text-color, #fff); position: sticky; top: 0; z-index: 2; }
.bar .menu { background: none; border: none; color: inherit; cursor: pointer; width: 40px; height: 40px; display: flex; align-items: center; justify-content: center; }
.bar .menu ha-icon { --mdc-icon-size: 24px; }
.bar h1 { font-size: 1.15em; font-weight: 400; margin: 0; flex: 1; }
.robots { display: flex; gap: 4px; }
.robots button { border: none; background: rgba(255,255,255,.15); color: inherit; padding: 6px 12px; border-radius: 999px; cursor: pointer; font-size: .85em; }
.robots button.on { background: rgba(255,255,255,.35); }
.wrap { display: grid; grid-template-columns: minmax(320px, 440px) 1fr; gap: 16px; padding: 16px; max-width: 1400px; margin: 0 auto; }
.wrap.narrow { grid-template-columns: 1fr; padding: 8px; }
.left, .right { min-width: 0; }
.tabs { display: flex; gap: 4px; overflow-x: auto; scrollbar-width: none; margin-bottom: 12px; }
.tabs button { flex: none; border: none; cursor: pointer; padding: 9px 14px; border-radius: 999px; font-size: .9em; display: flex; gap: 6px; align-items: center;
  background: color-mix(in srgb, var(--primary-text-color) 7%, transparent); color: var(--primary-text-color); }
.tabs button.on { background: var(--primary-color); color: var(--text-primary-color, #fff); }
.tabs button ha-icon { --mdc-icon-size: 18px; }
ha-card { display: block; margin-bottom: 12px; }
.card { padding: 14px 16px; }
h3 { margin: 0 0 10px; font-size: 1em; font-weight: 500; display: flex; align-items: center; justify-content: space-between; }
h5 { margin: 12px 0 6px; font-size: .76em; font-weight: 500; letter-spacing: .04em; text-transform: uppercase; color: var(--secondary-text-color); }
[hidden] { display: none !important; }
.btn { border: none; cursor: pointer; border-radius: 10px; padding: 9px 14px; font-size: .9em; display: inline-flex; align-items: center; gap: 6px;
  background: color-mix(in srgb, var(--primary-text-color) 7%, transparent); color: var(--primary-text-color); }
.btn.primary { background: var(--primary-color); color: var(--text-primary-color, #fff); }
.btn.danger { color: var(--error-color, #db4437); }
.btn ha-icon { --mdc-icon-size: 18px; }
.row { display: flex; align-items: center; gap: 10px; padding: 10px 0; border-bottom: 1px solid color-mix(in srgb, var(--primary-text-color) 10%, transparent); }
.row:last-child { border-bottom: none; }
.row .main { flex: 1; min-width: 0; }
.warn { color: var(--warning-color, #ff9800); font-size: .84em; display: flex; gap: 5px; align-items: center; margin-top: 3px; }
.warn ha-icon { --mdc-icon-size: 16px; }
.row .t { font-weight: 500; }
.row .s { font-size: .82em; color: var(--secondary-text-color); }
.row.off .main { opacity: .5; }
.switch { width: 42px; height: 24px; border-radius: 12px; border: none; cursor: pointer; position: relative; background: color-mix(in srgb, var(--primary-text-color) 20%, transparent); flex: none; }
.switch::after { content: ""; position: absolute; top: 3px; left: 3px; width: 18px; height: 18px; border-radius: 50%; background: #fff; transition: left .15s; }
.switch.on { background: var(--primary-color); }
.switch.on::after { left: 21px; }
.icon-btn { border: none; background: none; cursor: pointer; color: var(--secondary-text-color); width: 36px; height: 36px; border-radius: 10px; display: flex; align-items: center; justify-content: center; }
.icon-btn:hover { background: color-mix(in srgb, var(--primary-text-color) 8%, transparent); }
.form { display: grid; gap: 12px; }
.form label { display: block; font-size: .8em; color: var(--secondary-text-color); margin-bottom: 4px; }
.form input[type=time], .form select { width: 100%; box-sizing: border-box; padding: 9px 10px; border-radius: 10px; border: 1px solid color-mix(in srgb, var(--primary-text-color) 20%, transparent);
  background: var(--card-background-color); color: var(--primary-text-color); font-size: .95em; }
.chips { display: flex; flex-wrap: wrap; gap: 6px; }
.chip { border: none; cursor: pointer; padding: 7px 12px; border-radius: 999px; font-size: .86em;
  background: color-mix(in srgb, var(--primary-text-color) 7%, transparent); color: var(--primary-text-color); }
.chip.on { background: var(--primary-color); color: var(--text-primary-color, #fff); }
.seg { display: flex; gap: 4px; }
.seg button { flex: 1; border: none; cursor: pointer; padding: 8px 4px; border-radius: 8px; font-size: .84em;
  background: color-mix(in srgb, var(--primary-text-color) 7%, transparent); color: var(--primary-text-color); }
.seg button.on { background: var(--primary-color); color: var(--text-primary-color, #fff); }
.actions { display: flex; gap: 8px; justify-content: flex-end; }
.stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; }
.stat { padding: 12px; border-radius: 12px; background: color-mix(in srgb, var(--primary-text-color) 5%, transparent); }
.stat .v { font-size: 1.4em; font-weight: 500; }
.stat .l { font-size: .78em; color: var(--secondary-text-color); }
canvas.chart { width: 100%; height: 140px; display: block; }
.bar-row { display: grid; grid-template-columns: 110px 1fr 60px; gap: 10px; align-items: center; font-size: .86em; padding: 5px 0; }
.bar-row .track { height: 8px; border-radius: 4px; background: color-mix(in srgb, var(--primary-text-color) 10%, transparent); overflow: hidden; }
.bar-row .track > div { height: 100%; border-radius: 4px; background: var(--primary-color); }
.bar-row.warn .track > div { background: var(--warning-color, #ffa600); }
.bar-row.bad .track > div { background: var(--error-color, #db4437); }
.bar-row .r { text-align: right; color: var(--secondary-text-color); }
.dpad { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; max-width: 300px; margin: 14px auto; touch-action: none; user-select: none; -webkit-user-select: none; }
.dpad button { aspect-ratio: 1; border: none; border-radius: 14px; cursor: pointer; display: flex; align-items: center; justify-content: center;
  background: color-mix(in srgb, var(--primary-text-color) 8%, transparent); color: var(--primary-text-color); touch-action: none; -webkit-touch-callout: none; }
.dpad button ha-icon { --mdc-icon-size: 32px; pointer-events: none; }
.dpad button.held { background: var(--primary-color); color: var(--text-primary-color, #fff); }
.dpad button.halt { background: color-mix(in srgb, var(--error-color, #db4437) 18%, transparent); color: var(--error-color, #db4437); }
.dpad[aria-disabled="true"] button { opacity: .35; pointer-events: none; }
.drv-status { display: flex; align-items: center; gap: 8px; padding: 10px 12px; border-radius: 10px; margin-bottom: 8px; font-size: .9em;
  background: color-mix(in srgb, var(--primary-text-color) 6%, transparent); }
.drv-status.live { background: color-mix(in srgb, var(--primary-color) 16%, transparent); }
.drv-status ha-icon { --mdc-icon-size: 20px; flex: none; }
.note { font-size: .84em; color: var(--secondary-text-color); margin: 8px 0 0; }
.empty { padding: 24px; text-align: center; color: var(--secondary-text-color); }
.grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
.err { color: var(--error-color, #db4437); font-size: .86em; }
`;

class TapoRV30Panel extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: "open" });
    this._tab = "schedules";
    this._robot = null;
    this._editing = null;      // schedule being edited (object) or {} for new, or null
    this._records = null;
    this._recordsFor = null;
  }

  set panel(p) { this._panel = p; }
  set narrow(n) { this._narrow = n; this._layout(); }
  set route(r) { this._route = r; }
  set hass(hass) {
    const first = !this._hass;
    this._hass = hass;
    if (first) this._boot();
    else if (this._booted) this._update();
  }

  async _boot() {
    const url = this._panel && this._panel.config && this._panel.config.card_url;
    if (url && !customElements.get("tapo-rv30-card")) {
      try { await import(url); } catch (e) { /* the card is normally already loaded as a resource */ }
    }
    this.shadowRoot.innerHTML = `<style>${STYLE}</style>
      <div class="bar">
        <button class="menu" title="Menu"><ha-icon icon="mdi:menu"></ha-icon></button>
        <h1>Tapo Vacuum</h1>
        <div class="robots"></div>
      </div>
      <div class="wrap"><div class="left"></div><div class="right"></div></div>`;
    this.shadowRoot.querySelector(".menu").onclick = () =>
      this.dispatchEvent(new CustomEvent("hass-toggle-menu", { bubbles: true, composed: true }));
    this._layout();
    this._booted = true;
    this._update(true);
  }

  _layout() {
    const w = this.shadowRoot && this.shadowRoot.querySelector(".wrap");
    if (w) w.classList.toggle("narrow", !!this._narrow);
  }

  // ---- data ---------------------------------------------------------------------------
  _robots() {
    return Object.values(this._hass.states).filter((s) => s.entity_id.startsWith("vacuum.") && s.attributes.integration === DOMAIN);
  }
  _st(id) { return id ? this._hass.states[id] : undefined; }
  _related(vac) {
    const reg = this._hass.entities || {}, dev = reg[vac] && reg[vac].device_id;
    let ids = dev ? Object.keys(reg).filter((id) => reg[id].device_id === dev) : [];
    if (!ids.length) { const base = vac.split(".")[1]; ids = Object.keys(this._hass.states).filter((id) => id.split(".")[1].startsWith(base)); }
    const find = (prefix, needle) => ids.find((id) => id.startsWith(prefix) && (!needle || id.includes(needle)));
    const all = (prefix) => ids.filter((id) => id.startsWith(prefix)).sort();
    return {
      ids, camera: find("camera."), schedules: find("sensor.", "schedules"), status: find("sensor.", "status"),
      presets: all("button.").filter((id) => id.includes("preset")),
      switches: all("switch."), selects: all("select."), numbers: all("number."), times: all("time."),
      buttons: all("button.").filter((id) => !id.includes("preset")),
      totals: { cleans: find("sensor.", "total_cleans"), area: find("sensor.", "total_area"), time: find("sensor.", "total_cleaning_time") },
    };
  }
  _schedules(r) { const s = this._st(r.schedules); return (s && s.attributes.schedules) || []; }
  _dnd(r) { const s = this._st(r.schedules); return (s && s.attributes.dnd) || null; }
  _rooms(vac) { return (this._st(vac).attributes.rooms || []); }
  _presets(r) { return r.presets.map((id) => { const s = this._st(id); return { id: s.attributes.preset_id, name: s.attributes.preset_name || s.attributes.friendly_name, rooms: s.attributes.rooms }; }).filter((p) => p.id != null); }

  async _call(domain, service, data, target) {
    try { await this._hass.callService(domain, service, data, target); return true; }
    catch (e) {
      const message = (e && (e.message || (e.body && e.body.message))) || "The robot rejected that";
      this.dispatchEvent(new CustomEvent("hass-notification", { detail: { message }, bubbles: true, composed: true }));
      return false;
    }
  }

  // ---- render -------------------------------------------------------------------------
  _update(first) {
    const robots = this._robots();
    if (!robots.length) { this.shadowRoot.querySelector(".left").innerHTML = `<div class="empty">No Tapo robot vacuum is set up yet.</div>`; return; }
    if (!this._robot || !robots.some((r) => r.entity_id === this._robot)) this._robot = robots[0].entity_id;
    const rb = this.shadowRoot.querySelector(".robots");
    rb.innerHTML = robots.length > 1 ? robots.map((r) => `<button data-id="${esc(r.entity_id)}" class="${r.entity_id === this._robot ? "on" : ""}">${esc(r.attributes.friendly_name || r.entity_id)}</button>`).join("") : "";
    rb.querySelectorAll("button").forEach((b) => b.onclick = () => { this._robot = b.dataset.id; this._editing = null; this._records = null; this._update(true); });
    this._renderCard(first);
    this._renderRight(first);
  }

  _renderCard(first) {
    const left = this.shadowRoot.querySelector(".left");
    let card = left.querySelector("tapo-rv30-card");
    if (!card || card._config.entity !== this._robot) {
      left.innerHTML = "";
      card = document.createElement("tapo-rv30-card");
      card.setConfig({ entity: this._robot });
      left.appendChild(card);
    }
    card.hass = this._hass;
  }

  _renderRight(first) {
    const right = this.shadowRoot.querySelector(".right");
    const tabs = [["schedules", "mdi:calendar-clock", "Schedules"], ["history", "mdi:history", "History"], ["rooms", "mdi:floor-plan", "Rooms"],
                  ["drive", "mdi:gamepad-variant", "Drive"], ["maintenance", "mdi:wrench", "Maintenance"], ["settings", "mdi:tune", "Settings"]];
    if (!right.querySelector(".tabs")) {
      right.innerHTML = `<div class="tabs">${tabs.map(([k, i, l]) => `<button data-tab="${k}"><ha-icon icon="${i}"></ha-icon>${l}</button>`).join("")}</div><div class="pane"></div>`;
      right.querySelectorAll(".tabs button").forEach((b) => b.onclick = () => { if (this._stopDrive) this._stopDrive(); this._tab = b.dataset.tab; this._editing = null; this._renderRight(true); });
    }
    right.querySelectorAll(".tabs button").forEach((b) => b.classList.toggle("on", b.dataset.tab === this._tab));
    const pane = right.querySelector(".pane");
    const sig = JSON.stringify([this._tab, this._robot, this._editing && this._editing.id, this._signature()]);
    if (!first && sig === this._paneSig) return;
    this._paneSig = sig;
    ({ schedules: this._paneSchedules, history: this._paneHistory, rooms: this._paneRooms, drive: this._paneDrive,
       maintenance: this._paneMaintenance, settings: this._paneSettings }[this._tab]).call(this, pane);
  }

  _signature() {
    const r = this._related(this._robot);
    const pick = (ids) => ids.map((id) => { const s = this._st(id); return s ? s.state + JSON.stringify(s.attributes) : ""; }).join("|");
    return pick([this._robot, r.camera, r.schedules, r.status, ...r.switches, ...r.selects, ...r.numbers, ...r.times, ...r.presets]);
  }

  // ---- schedules ----------------------------------------------------------------------
  _paneSchedules(pane) {
    const r = this._related(this._robot), list = this._schedules(r), dnd = this._dnd(r);
    if (this._editing) return this._renderEditor(pane, r);
    const rows = list.map((s) => {
      const blocked = s.blocked_by_dnd != null ? s.blocked_by_dnd : inDnd(dnd, s.time);
      const warn = blocked && dnd ? `<div class="warn"><ha-icon icon="mdi:bell-sleep"></ha-icon>Inside ${esc(dndText(dnd))}: the robot will skip it</div>` : "";
      const target = s.preset_id != null ? `Preset ${esc((this._presets(r).find((p) => p.id === s.preset_id) || {}).name || s.preset_id)}`
        : (s.rooms && s.rooms.length ? esc(s.rooms.join(", ")) : "Whole house");
      const days = (s.days || []).length === 7 ? "Daily" : (s.days || []).join(" ");
      const levels = [s.suction != null ? FAN[s.suction - 1] : null, s.water_level != null ? `water ${WATER[s.water_level]}` : null, s.clean_passes ? `${s.clean_passes}x` : null].filter(Boolean).join(", ");
      return `<div class="row ${s.enabled ? "" : "off"}" data-id="${esc(s.id)}">
        <button class="switch ${s.enabled ? "on" : ""}" data-act="toggle" title="${s.enabled ? "Disable" : "Enable"}"></button>
        <div class="main"><div class="t">${esc(s.time)} &middot; ${esc(days)}</div><div class="s">${target}${levels ? " &middot; " + esc(levels) : ""}</div>${warn}</div>
        <button class="icon-btn" data-act="edit" title="Edit"><ha-icon icon="mdi:pencil"></ha-icon></button>
        <button class="icon-btn" data-act="delete" title="Delete"><ha-icon icon="mdi:delete"></ha-icon></button>
      </div>`;
    }).join("");
    pane.innerHTML = `<ha-card><div class="card">
      <h3><span>Schedules on the robot</span><button class="btn primary" data-act="add"><ha-icon icon="mdi:plus"></ha-icon>Add</button></h3>
      ${rows || `<div class="empty">No schedules yet. They run on the robot itself, app or not.</div>`}
    </div></ha-card>`;
    pane.querySelector('[data-act="add"]').onclick = () => { this._editing = {}; this._renderRight(true); };
    pane.querySelectorAll(".row").forEach((row) => {
      const s = list.find((x) => String(x.id) === row.dataset.id);
      row.querySelector('[data-act="toggle"]').onclick = () => {
        const data = { schedule_id: s.id, enabled: !s.enabled };
        if (!s.enabled && inDnd(dnd, s.time)) {
          if (!confirm(`${s.time} is inside ${dndText(dnd)}, so the robot will not run this schedule. Enable it anyway?`)) return;
          data.ignore_dnd = true;
        }
        this._call(DOMAIN, "set_schedule", data, { entity_id: this._robot });
      };
      row.querySelector('[data-act="edit"]').onclick = () => { this._editing = { ...s }; this._renderRight(true); };
      row.querySelector('[data-act="delete"]').onclick = async () => {
        if (!confirm(`Delete the ${s.time} schedule from the robot?`)) return;
        await this._call(DOMAIN, "remove_schedule", { schedule_id: s.id }, { entity_id: this._robot });
      };
    });
  }

  _renderEditor(pane, r) {
    const s = this._editing, isNew = s.id == null;
    const rooms = this._rooms(this._robot), presets = this._presets(r), dnd = this._dnd(r);
    const state = {
      time: s.time || "09:00", days: new Set((s.days || []).map((d) => d.slice(0, 3))),
      mode: s.preset_id != null ? "preset" : (s.rooms && s.rooms.length ? "rooms" : "house"),
      rooms: new Set(s.rooms || []), preset: s.preset_id != null ? String(s.preset_id) : (presets[0] ? String(presets[0].id) : ""),
      suction: s.suction || 0, water: s.water_level == null ? -1 : s.water_level, passes: s.clean_passes || 0, enabled: s.enabled !== false,
    };
    const dayChips = () => DAYS.map((d) => `<button class="chip ${state.days.has(d) ? "on" : ""}" data-day="${d}">${d}</button>`).join("") +
      `<button class="chip" data-quick="daily">Daily</button><button class="chip" data-quick="weekdays">Weekdays</button><button class="chip" data-quick="weekend">Weekend</button>`;
    const roomChips = () => rooms.map((n) => `<button class="chip ${state.rooms.has(n) ? "on" : ""}" data-room="${esc(n)}">${esc(n)}</button>`).join("");
    pane.innerHTML = `<ha-card><div class="card form">
      <h3><span>${isNew ? "New schedule" : `Edit schedule ${esc(s.id)}`}</span></h3>
      <div><label>Start time (robot's time zone)</label><input type="time" value="${esc(state.time)}">
        <div class="warn dnd" hidden><ha-icon icon="mdi:bell-sleep"></ha-icon><span></span></div></div>
      <div><label>Days</label><div class="chips days">${dayChips()}</div></div>
      <div><label>What to clean</label><div class="seg mode">
        <button data-mode="house" class="${state.mode === "house" ? "on" : ""}">Whole house</button>
        <button data-mode="rooms" class="${state.mode === "rooms" ? "on" : ""}">Rooms</button>
        <button data-mode="preset" class="${state.mode === "preset" ? "on" : ""}" ${presets.length ? "" : "disabled"}>Preset</button></div></div>
      <div class="rooms-box" ${state.mode === "rooms" ? "" : "hidden"}><div class="chips rooms">${roomChips()}</div></div>
      <div class="preset-box" ${state.mode === "preset" ? "" : "hidden"}><select class="preset">${presets.map((p) => `<option value="${p.id}" ${String(p.id) === state.preset ? "selected" : ""}>${esc(p.name)}</option>`).join("")}</select></div>
      <div class="grid2">
        <div><label>Suction</label><select class="suction"><option value="0">Robot default</option>${FAN.map((f, i) => `<option value="${i + 1}" ${state.suction === i + 1 ? "selected" : ""}>${f}</option>`).join("")}</select></div>
        <div><label>Water</label><select class="water"><option value="-1">Robot default</option>${WATER.map((w, i) => `<option value="${i}" ${state.water === i ? "selected" : ""}>${w}</option>`).join("")}</select></div>
      </div>
      <div class="grid2">
        <div><label>Passes</label><select class="passes"><option value="0">Robot default</option>${[1, 2, 3].map((n) => `<option value="${n}" ${state.passes === n ? "selected" : ""}>${n}</option>`).join("")}</select></div>
        <div><label>Enabled</label><button class="switch enabled ${state.enabled ? "on" : ""}" style="margin-top:6px"></button></div>
      </div>
      <div class="err" hidden></div>
      <div class="actions"><button class="btn cancel">Cancel</button><button class="btn primary save"><ha-icon icon="mdi:content-save"></ha-icon>${isNew ? "Add to robot" : "Save"}</button></div>
    </div></ha-card>`;
    const q = (sel) => pane.querySelector(sel);
    const redrawDays = () => { q(".days").innerHTML = dayChips(); bindDays(); };
    const bindDays = () => {
      q(".days").querySelectorAll("[data-day]").forEach((b) => b.onclick = () => { state.days.has(b.dataset.day) ? state.days.delete(b.dataset.day) : state.days.add(b.dataset.day); redrawDays(); });
      q(".days").querySelectorAll("[data-quick]").forEach((b) => b.onclick = () => {
        const sets = { daily: DAYS, weekdays: DAYS.slice(0, 5), weekend: DAYS.slice(5) };
        state.days = new Set(sets[b.dataset.quick]); redrawDays();
      });
    };
    const dndCheck = () => {
      const w = q(".warn.dnd"), t = q("input[type=time]").value;
      const hit = dnd && dnd.enabled && inDnd(dnd, t);
      w.hidden = !hit;
      if (hit) w.querySelector("span").textContent = `${t} is inside ${dndText(dnd)}: the robot will not run it. Pick another time or change the window in Settings.`;
      return hit;
    };
    q("input[type=time]").oninput = dndCheck; dndCheck();
    bindDays();
    q(".rooms").querySelectorAll("[data-room]").forEach((b) => b.onclick = () => { const n = b.dataset.room; state.rooms.has(n) ? state.rooms.delete(n) : state.rooms.add(n); b.classList.toggle("on"); });
    q(".mode").querySelectorAll("button").forEach((b) => b.onclick = () => {
      state.mode = b.dataset.mode; q(".mode").querySelectorAll("button").forEach((o) => o.classList.toggle("on", o === b));
      q(".rooms-box").hidden = state.mode !== "rooms"; q(".preset-box").hidden = state.mode !== "preset";
    });
    q(".enabled").onclick = () => { state.enabled = !state.enabled; q(".enabled").classList.toggle("on", state.enabled); };
    q(".cancel").onclick = () => { this._editing = null; this._renderRight(true); };
    q(".save").onclick = async () => {
      const err = q(".err"); err.hidden = true;
      const time = q("input[type=time]").value;
      if (!time) { err.textContent = "Pick a start time."; err.hidden = false; return; }
      if (!state.days.size) { err.textContent = "Pick at least one day (the robot only keeps repeating schedules)."; err.hidden = false; return; }
      if (state.mode === "rooms" && !state.rooms.size) { err.textContent = "Pick at least one room."; err.hidden = false; return; }
      const data = { time, days: [...state.days], enabled: state.enabled };
      if (state.mode === "rooms") data.rooms = [...state.rooms];
      else if (state.mode === "preset") data.preset = q(".preset").value;
      else data.rooms = [];
      const su = Number(q(".suction").value), wa = Number(q(".water").value), pa = Number(q(".passes").value);
      if (su) data.suction = FAN[su - 1]; if (wa >= 0) data.water = WATER[wa]; if (pa) data.passes = pa;
      if (!isNew) data.schedule_id = s.id;
      if (state.enabled && dndCheck()) {
        if (!confirm(`${time} is inside ${dndText(dnd)}. The robot will keep the schedule but never run it until the time or the window changes. Save anyway?`)) return;
        data.ignore_dnd = true;
      }
      const ok = await this._call(DOMAIN, isNew ? "add_schedule" : "set_schedule", data, { entity_id: this._robot });
      if (ok) { this._editing = null; this._renderRight(true); }
    };
  }

  // ---- history and stats --------------------------------------------------------------
  async _paneHistory(pane) {
    const r = this._related(this._robot);
    const tot = (id) => { const s = this._st(id); return s ? s.state : "–"; };
    pane.innerHTML = `<ha-card><div class="card">
      <h3><span>Statistics</span></h3>
      <div class="stats"><div class="stat"><div class="v">${esc(tot(r.totals.cleans))}</div><div class="l">cleans</div></div>
        <div class="stat"><div class="v">${esc(tot(r.totals.area))}</div><div class="l">m² cleaned</div></div>
        <div class="stat"><div class="v">${esc(tot(r.totals.time))}</div><div class="l">hours</div></div></div>
      <h5>Cleans per day, last 30 days</h5><canvas class="chart days"></canvas>
      <h5>Minutes per week, last 8 weeks</h5><canvas class="chart weeks"></canvas>
    </div></ha-card>
    <ha-card><div class="card"><h3><span>Recent runs</span></h3><div class="runs"><div class="empty">Loading</div></div></div></ha-card>`;
    if (!this._records || this._recordsFor !== this._robot) {
      try {
        const resp = await this._hass.connection.sendMessagePromise({ type: "call_service", domain: DOMAIN, service: "get_clean_records",
          service_data: { entity_id: this._robot, limit: 100 }, return_response: true });
        this._records = (resp && resp.response && resp.response.records) || []; this._recordsFor = this._robot;
      } catch (e) { this._records = []; }
    }
    const recs = this._records;
    const runs = pane.querySelector(".runs");
    runs.innerHTML = recs.length ? recs.slice(0, 20).map((x) => {
      const d = x.started ? new Date(x.started * 1000) : null;
      const when = d ? d.toLocaleDateString(undefined, { weekday: "short", day: "numeric", month: "short" }) + " " + d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" }) : "";
      const meta = [x.area != null ? `${x.area} m²` : null, x.minutes != null ? `${x.minutes} min` : null, START[x.start_type] || null, x.rule_name || null, x.emptied_bin ? "bin emptied" : null].filter(Boolean).join(" · ");
      return `<div class="row"><ha-icon icon="${x.error ? "mdi:alert-circle" : "mdi:robot-vacuum"}" style="color:${x.error ? "var(--error-color,#db4437)" : "var(--primary-color)"}"></ha-icon><div class="main"><div class="t">${esc(when)}</div><div class="s">${esc(meta)}${x.error ? ` · error ${x.error}` : ""}</div></div></div>`;
    }).join("") : `<div class="empty">No runs recorded yet.</div>`;
    this._chart(pane.querySelector("canvas.days"), this._perDay(recs, 30), (i) => (i % 7 === 0 ? `${29 - i}d` : ""));
    this._chart(pane.querySelector("canvas.weeks"), this._perWeek(recs, 8), (i) => (i === 7 ? "this wk" : `-${7 - i}`));
  }

  _perDay(recs, n) {
    const out = new Array(n).fill(0), now = Math.floor(Date.now() / 86400000);
    for (const x of recs) { if (!x.started) continue; const d = now - Math.floor(x.started / 86400); if (d >= 0 && d < n) out[n - 1 - d] += 1; }
    return out;
  }
  _perWeek(recs, n) {
    const out = new Array(n).fill(0), now = Math.floor(Date.now() / 604800000);
    for (const x of recs) { if (!x.started) continue; const w = now - Math.floor(x.started / 604800); if (w >= 0 && w < n) out[n - 1 - w] += x.minutes || 0; }
    return out;
  }
  _chart(canvas, values, label) {
    if (!canvas) return;
    const dpr = window.devicePixelRatio || 1, W = canvas.clientWidth || 400, H = 140;
    canvas.width = W * dpr; canvas.height = H * dpr;
    const ctx = canvas.getContext("2d"); ctx.scale(dpr, dpr);
    const cs = getComputedStyle(this), primary = cs.getPropertyValue("--primary-color").trim() || "#03a9f4", text = cs.getPropertyValue("--secondary-text-color").trim() || "#888";
    const max = Math.max(1, ...values), n = values.length, gap = 3, bw = (W - gap * (n - 1)) / n, base = H - 18;
    ctx.font = "11px sans-serif"; ctx.textAlign = "center";
    values.forEach((v, i) => {
      const h = Math.round((base - 14) * v / max), x = i * (bw + gap);
      ctx.fillStyle = v ? primary : text; ctx.globalAlpha = v ? 1 : .18;
      ctx.beginPath(); ctx.roundRect(x, base - Math.max(h, 2), bw, Math.max(h, 2), 2); ctx.fill(); ctx.globalAlpha = 1;
      if (v) { ctx.fillStyle = text; ctx.fillText(String(v), x + bw / 2, base - h - 3); }
      const l = label(i); if (l) { ctx.fillStyle = text; ctx.fillText(l, x + bw / 2, H - 4); }
    });
  }

  // ---- rooms ---------------------------------------------------------------------------
  _paneRooms(pane) {
    const r = this._related(this._robot), cam = this._st(r.camera), geom = (cam && cam.attributes.room_geometry) || [];
    const fresh = (cam && cam.attributes.rooms_last_cleaned) || {};
    const rows = geom.map((g) => {
      const f = fresh[g.name] || {}, cov = f.coverage || 0, d = f.last_cleaned ? (Date.now() / 1000 - f.last_cleaned) / 86400 : null;
      const cls = d == null ? "bad" : d > 7 ? "warn" : "";
      return `<div class="bar-row ${cls}"><span>${esc(g.name)}</span><div class="track"><div style="width:${cov}%"></div></div><span class="r">${esc(ago(f.last_cleaned))}</span></div>
        <div class="actions" style="justify-content:flex-start;margin:-2px 0 6px"><button class="btn" data-room="${esc(g.name)}"><ha-icon icon="mdi:play"></ha-icon>Clean ${esc(g.name)}</button>
        <span class="s" style="font-size:.8em;color:var(--secondary-text-color);align-self:center">${f.coverage != null ? `${f.coverage}% covered last time` : "not cleaned since the map was made"}${g.suction ? ` · ${FAN[g.suction - 1]}` : ""}${g.passes ? ` · ${g.passes}x` : ""}</span></div>`;
    }).join("");
    pane.innerHTML = `<ha-card><div class="card"><h3><span>Rooms and freshness</span></h3>${rows || `<div class="empty">No rooms on the current map.</div>`}</div></ha-card>`;
    pane.querySelectorAll("[data-room]").forEach((b) => b.onclick = () => this._call(DOMAIN, "clean_rooms", { rooms: [b.dataset.room] }, { entity_id: this._robot }));
  }

  // ---- maintenance ---------------------------------------------------------------------
  // ---- drive (the app's remote control) ------------------------------------------------
  _paneDrive(pane) {
    const r = this._related(this._robot), vac = this._st(this._robot), st = this._st(r.status);
    const supported = vac.attributes.remote_control !== false;
    const text = st ? st.state : vac.state, remote = text === "Remote Control";
    const sweep = r.switches.find((id) => /sweep_walk|clean_while/.test(id)), sw = sweep ? this._st(sweep) : null;
    if (!pane.querySelector(".dpad")) {
      if (!supported) { pane.innerHTML = `<ha-card><div class="card"><div class="empty">This robot has no remote control.</div></div></ha-card>`; return; }
      pane.innerHTML = `<ha-card><div class="card" tabindex="0">
        <h3><span>Drive</span><span class="actions"><button class="btn primary take"><ha-icon icon="mdi:gamepad-variant"></ha-icon>Take control</button><button class="btn give" hidden><ha-icon icon="mdi:hand-back-left"></ha-icon>Hand back</button></span></h3>
        <div class="drv-status"><ha-icon icon="mdi:robot-vacuum"></ha-icon><span></span></div>
        <div class="dpad" aria-disabled="true">
          <span></span><button data-dir="forward" title="Forward (up arrow)"><ha-icon icon="mdi:arrow-up-bold"></ha-icon></button><span></span>
          <button data-dir="left" title="Turn left (left arrow)"><ha-icon icon="mdi:arrow-left-bold"></ha-icon></button>
          <button class="halt" data-dir="stop" title="Stop (space)"><ha-icon icon="mdi:stop"></ha-icon></button>
          <button data-dir="right" title="Turn right (right arrow)"><ha-icon icon="mdi:arrow-right-bold"></ha-icon></button>
          <span></span><button data-dir="backward" title="Backward (down arrow)"><ha-icon icon="mdi:arrow-down-bold"></ha-icon></button><span></span>
        </div>
        <div class="actions" style="justify-content:center;flex-wrap:wrap">
          ${sweep ? `<button class="btn sweep"><ha-icon icon="mdi:broom"></ha-icon><span>Vacuum while driving</span></button>` : ""}
          <button class="btn spot"><ha-icon icon="mdi:target"></ha-icon>Spot clean here</button>
          <button class="btn locate"><ha-icon icon="mdi:map-marker-radius"></ha-icon>Locate</button>
          <button class="btn dock"><ha-icon icon="mdi:home-import-outline"></ha-icon>Send home</button>
        </div>
        <p class="note">Take control and the robot drives off the dock. It moves while you hold a button or an arrow key and stops when you let go. Hand back control, or send it home, when you are done.</p>
      </div></ha-card>`;
      const q = (s) => pane.querySelector(s), dpad = q(".dpad");
      const send = (command) => this._hass.callService(DOMAIN, "remote_drive", { command }, { entity_id: this._robot }, false, true);
      const fail = (e) => this.dispatchEvent(new CustomEvent("hass-notification", { detail: { message: (e && (e.message || (e.body && e.body.message))) || "The robot rejected that" }, bubbles: true, composed: true }));
      let held = null;
      const paint = () => dpad.querySelectorAll("[data-dir]").forEach((b) => b.classList.toggle("held", b.dataset.dir === held));
      const loop = async (dir) => {
        // like the app: send, wait for the answer, pause 300 ms, repeat while still held
        while (held === dir) {
          try { await send(dir); } catch (e) { held = null; paint(); fail(e); return; }
          await new Promise((res) => setTimeout(res, 300));
        }
      };
      const start = (dir) => { if (dpad.getAttribute("aria-disabled") === "true" || held === dir) return; held = dir; paint(); loop(dir); };
      const stop = () => { if (held == null) return; held = null; paint(); send("stop").catch(fail); };
      dpad.querySelectorAll("[data-dir]").forEach((b) => {
        if (b.dataset.dir === "stop") { b.onclick = () => { held = null; paint(); send("stop").catch(fail); }; return; }
        b.onpointerdown = (e) => { e.preventDefault(); b.setPointerCapture(e.pointerId); start(b.dataset.dir); };
        b.onpointerup = b.onpointercancel = b.onlostpointercapture = () => stop();
        b.oncontextmenu = (e) => e.preventDefault();
      });
      const keys = { ArrowUp: "forward", ArrowDown: "backward", ArrowLeft: "left", ArrowRight: "right" };
      q(".card").onkeydown = (e) => { if (e.repeat) return; if (keys[e.key]) { e.preventDefault(); start(keys[e.key]); } else if (e.key === " ") { e.preventDefault(); stop(); } };
      q(".card").onkeyup = (e) => { if (keys[e.key] && held === keys[e.key]) stop(); };
      window.addEventListener("blur", stop);
      this._stopDrive = stop;
      q(".take").onclick = async () => {
        try {
          const res = await send("enter");
          const ms = (res && res.response && res.response.leaving_dock_ms) || 4000;
          this._entered = true; dpad.setAttribute("aria-disabled", "false"); q(".take").hidden = true; q(".give").hidden = false;
          q(".drv-status").classList.add("live"); q(".drv-status span").textContent = "Remote control: leaving the dock";
          this.dispatchEvent(new CustomEvent("hass-notification", { detail: { message: `You have the controls. Give it ${Math.round(ms / 1000)} s to leave the dock.` }, bubbles: true, composed: true }));
        } catch (e) { fail(e); }
      };
      q(".give").onclick = () => { stop(); this._entered = false; send("exit").catch(fail); };
      q(".spot").onclick = () => { stop(); this._call("vacuum", "clean_spot", {}, { entity_id: this._robot }); };
      q(".locate").onclick = () => this._call("vacuum", "locate", {}, { entity_id: this._robot });
      q(".dock").onclick = async () => { stop(); this._entered = false; try { await send("exit"); } catch (e) { /* not in control */ } this._call("vacuum", "return_to_base", {}, { entity_id: this._robot }); };
      if (sweep) q(".sweep").onclick = () => this._call("switch", (this._st(sweep).state === "on") ? "turn_off" : "turn_on", {}, { entity_id: sweep });
    }
    const live = remote || !!this._entered;
    const s = pane.querySelector(".drv-status");
    s.classList.toggle("live", live);
    s.querySelector("span").textContent = !live ? `Robot is ${String(text).toLowerCase()}. Take control to drive it.`
      : remote ? "You have the controls. Hold an arrow to drive." : `Remote control requested, robot reports ${String(text).toLowerCase()}`;
    pane.querySelector(".dpad").setAttribute("aria-disabled", live ? "false" : "true");
    pane.querySelector(".take").hidden = live; pane.querySelector(".give").hidden = !live;
    if (sw) { const b = pane.querySelector(".sweep"); b.classList.toggle("primary", sw.state === "on"); b.querySelector("span").textContent = sw.state === "on" ? "Vacuuming while driving" : "Vacuum while driving"; }
  }

  _paneMaintenance(pane) {
    const r = this._related(this._robot), vac = this._st(this._robot), cons = vac.attributes.consumables || {};
    const bars = Object.entries(cons).map(([k, v]) => `<div class="bar-row ${v <= 10 ? "bad" : v <= 30 ? "warn" : ""}"><span>${esc(k)}</span><div class="track"><div style="width:${v}%"></div></div><span class="r">${v}%</span></div>`).join("");
    const btns = r.buttons.map((id) => { const s = this._st(id); return `<button class="btn" data-btn="${esc(id)}"><ha-icon icon="${esc(s.attributes.icon || "mdi:gesture-tap-button")}"></ha-icon>${esc(s.attributes.friendly_name.replace(vac.attributes.friendly_name + " ", ""))}</button>`; }).join(" ");
    pane.innerHTML = `<ha-card><div class="card"><h3><span>Consumables</span></h3>${bars || `<div class="empty">No consumable data.</div>`}</div></ha-card>
      <ha-card><div class="card"><h3><span>Actions</span></h3><div class="chips">${btns}</div></div></ha-card>`;
    pane.querySelectorAll("[data-btn]").forEach((b) => b.onclick = () => this._call("button", "press", {}, { entity_id: b.dataset.btn }));
  }

  // ---- settings ------------------------------------------------------------------------
  _paneSettings(pane) {
    const r = this._related(this._robot), vac = this._st(this._robot), strip = (n) => n.replace(vac.attributes.friendly_name + " ", "");
    const sw = r.switches.map((id) => { const s = this._st(id); return `<div class="row"><div class="main"><div class="t">${esc(strip(s.attributes.friendly_name))}</div></div><button class="switch ${s.state === "on" ? "on" : ""}" data-sw="${esc(id)}"></button></div>`; }).join("");
    const sel = r.selects.map((id) => { const s = this._st(id); return `<div class="row"><div class="main"><div class="t">${esc(strip(s.attributes.friendly_name))}</div></div><select data-sel="${esc(id)}">${(s.attributes.options || []).map((o) => `<option ${o === s.state ? "selected" : ""}>${esc(o)}</option>`).join("")}</select></div>`; }).join("");
    const num = r.numbers.map((id) => { const s = this._st(id); return `<div class="row"><div class="main"><div class="t">${esc(strip(s.attributes.friendly_name))}</div><div class="s">${esc(s.state)} ${esc(s.attributes.unit_of_measurement || "")}</div></div><input type="range" data-num="${esc(id)}" min="${s.attributes.min}" max="${s.attributes.max}" step="${s.attributes.step || 1}" value="${esc(s.state)}"></div>`; }).join("");
    const tim = r.times.map((id) => { const s = this._st(id); return `<div class="row"><div class="main"><div class="t">${esc(strip(s.attributes.friendly_name))}</div></div><input type="time" data-time="${esc(id)}" value="${esc(String(s.state).slice(0, 5))}"></div>`; }).join("");
    pane.innerHTML = `<ha-card><div class="card"><h3><span>Settings</span></h3>${sw}${sel}${tim}${num}${(sw || sel || num || tim) ? "" : `<div class="empty">No settings entities.</div>`}</div></ha-card>`;
    pane.querySelectorAll("[data-sw]").forEach((b) => b.onclick = () => this._call("switch", b.classList.contains("on") ? "turn_off" : "turn_on", {}, { entity_id: b.dataset.sw }));
    pane.querySelectorAll("[data-sel]").forEach((e) => e.onchange = () => this._call("select", "select_option", { option: e.value }, { entity_id: e.dataset.sel }));
    pane.querySelectorAll("[data-num]").forEach((e) => e.onchange = () => this._call("number", "set_value", { value: Number(e.value) }, { entity_id: e.dataset.num }));
    pane.querySelectorAll("[data-time]").forEach((e) => e.onchange = () => { if (e.value) this._call("time", "set_value", { time: e.value + ":00" }, { entity_id: e.dataset.time }); });
  }
}
customElements.define("tapo-rv30-panel", TapoRV30Panel);
