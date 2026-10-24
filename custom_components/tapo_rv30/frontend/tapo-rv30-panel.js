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
// A .switch toggle that names what it controls and says whether it is on (screen readers see nothing else).
// clean_rooms data for rooms read from one map: with map_id the service refuses them once the robot
// is on another map, instead of cleaning a room there that happens to have the same id or name.
const onMap = (data, mapId) => (Number.isInteger(mapId) ? { ...data, map_id: mapId } : data);
// A number from entity state for markup (style widths, attribute values): never raw text.
const toNum = (v, fallback = 0) => { const n = Number(v); return Number.isFinite(n) ? n : fallback; };
// An id made from a name the way Home Assistant makes entity ids ("Jarvis Robot" -> "jarvis_robot").
const slug = (n) => String(n || "").normalize("NFKD").replace(/[\u0300-\u036f]/g, "").toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
const objectId = (id) => id.slice(id.indexOf(".") + 1);
const toggle = (on, label, attrs = "") => `<button class="switch ${on ? "on" : ""}" aria-pressed="${on ? "true" : "false"}" aria-label="${esc(label)}" ${attrs}></button>`;
// Local calendar day number (DST-safe), so charts bucket runs by the viewer's own midnight.
const localDay = (ms) => { const d = new Date(ms); return Math.round(Date.UTC(d.getFullYear(), d.getMonth(), d.getDate()) / 86400000); };
// Attributes that change on every poll while the robot runs; none of the panes show them, and
// leaving them in the pane signature re-rendered (and wiped) open forms every few seconds.
const VOLATILE = new Set(["position_mm", "clean_area", "clean_time_min", "clean_percent", "current_room", "battery_level", "battery_icon",
  "path_points", "entity_picture", "access_token", "last_clean", "last_clean_url", "calibration_points", "prompts"]);
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
.etools { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; margin-bottom: 8px; }
.etool.on { background: var(--primary-color); color: var(--text-primary-color, #fff); }
.efurn { padding: 7px 10px; border-radius: 10px; border: 1px solid var(--divider-color); background: var(--card-background-color); color: var(--primary-text-color); }
.ehint { font-size: .8em; color: var(--secondary-text-color); margin-bottom: 8px; }
.estage { background: #1b1b1b; border-radius: 10px; overflow: hidden; line-height: 0; }
.ecanvas { width: 100%; height: auto; display: block; touch-action: none; cursor: crosshair; }
.erooms { margin-top: 10px; } .erooms h5 { margin: 6px 0; }
.erooms input { width: 150px; padding: 5px 8px; border-radius: 8px; border: 1px solid var(--divider-color); background: var(--card-background-color); color: var(--primary-text-color); }
.ebtns { display: flex; gap: 8px; margin-top: 12px; align-items: center; flex-wrap: wrap; }
.estatus { margin-top: 8px; min-height: 1.2em; }
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
.plan-next { font-size: 1.3em; font-weight: 500; margin: 2px 0 4px; }
.plan-sub { color: var(--secondary-text-color); font-size: .9em; }
.chip.warn { background: color-mix(in srgb, var(--warning-color, #ffa600) 18%, transparent); color: var(--primary-text-color); cursor: default; }
.chip.info { cursor: default; }
.banner { display: flex; gap: 10px; align-items: center; padding: 10px 12px; border-radius: 10px; font-size: .88em; margin: 10px 0 0;
  background: color-mix(in srgb, var(--primary-color) 12%, transparent); }
.banner ha-icon { --mdc-icon-size: 20px; flex: none; }
.banner .grow { flex: 1; }
.proom { display: grid; grid-template-columns: minmax(80px, 1fr) minmax(90px, 1.4fr) 130px 92px; gap: 8px 12px; align-items: center; padding: 10px 0;
  border-bottom: 1px solid color-mix(in srgb, var(--primary-text-color) 10%, transparent); font-size: .9em; }
.proom:last-child { border-bottom: none; }
.proom .nm { font-weight: 500; }
.proom select { width: 100%; }
.proom .pill { justify-self: end; }
.wrap.narrow .proom { grid-template-columns: 1fr 120px; grid-template-areas: "nm pill" "bar sel" "sub sub" "ed ed"; }
.wrap.narrow .proom .nm { grid-area: nm; }
.wrap.narrow .proom .pill { grid-area: pill; }
.wrap.narrow .proom .fresh-cell { grid-area: bar; }
.wrap.narrow .proom select { grid-area: sel; }
.wrap.narrow .proom .sub { grid-area: sub; }
.wrap.narrow .proom .sensors { grid-area: ed; }
.proom .sub { grid-column: 1 / -1; display: flex; flex-wrap: wrap; gap: 6px 10px; align-items: center; font-size: .82em; color: var(--secondary-text-color); }
.proom .sub button { border: none; background: none; color: var(--primary-color); cursor: pointer; padding: 0; font-size: 1em; }
.proom select, .cond select, .cond input[type=time] { padding: 6px 8px; border-radius: 8px; border: 1px solid color-mix(in srgb, var(--primary-text-color) 20%, transparent);
  background: var(--card-background-color); color: var(--primary-text-color); font-size: .9em; }
.fbar { height: 8px; border-radius: 4px; background: color-mix(in srgb, var(--primary-text-color) 10%, transparent); overflow: hidden; }
.fbar > div { height: 100%; border-radius: 4px; background: var(--primary-color); }
.fbar.due > div { background: var(--warning-color, #ffa600); }
.ago { font-size: .8em; color: var(--secondary-text-color); margin-top: 3px; }
.pill { padding: 4px 9px; border-radius: 999px; font-size: .8em; white-space: nowrap; background: color-mix(in srgb, var(--primary-text-color) 7%, transparent); }
.pill.over, .pill.due { background: color-mix(in srgb, var(--warning-color, #ffa600) 20%, transparent); }
.pill.fresh { background: color-mix(in srgb, var(--success-color, #43a047) 20%, transparent); }
.pill.out { opacity: .6; }
.sensors { grid-column: 1 / -1; padding: 10px; border-radius: 10px; background: color-mix(in srgb, var(--primary-text-color) 4%, transparent); }
.cond { display: grid; gap: 8px; }
.cond .c { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 12px; padding: 10px 12px; border-radius: 10px;
  background: color-mix(in srgb, var(--primary-text-color) 4%, transparent); font-size: .9em; }
.cond .c small { display: block; color: var(--secondary-text-color); font-size: .86em; margin-top: 2px; }
.cond .c small.err { color: var(--error-color, #db4437); }
.cond .c .ctl { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; justify-content: flex-end; }
.cond .people { padding: 0 12px 4px; }
.log .e { display: flex; gap: 12px; padding: 7px 0; border-bottom: 1px solid color-mix(in srgb, var(--primary-text-color) 8%, transparent); font-size: .88em; }
.log .e:last-child { border-bottom: none; }
.log .e b { font-weight: 400; color: var(--secondary-text-color); width: 96px; flex: none; }
.empty { padding: 24px; text-align: center; color: var(--secondary-text-color); }
.grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
.err { color: var(--error-color, #db4437); font-size: .86em; }
.bkgrid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 12px; }
.bkcard { border-radius: 12px; overflow: hidden; background: color-mix(in srgb, var(--primary-text-color) 4%, transparent); border: 1px solid color-mix(in srgb, var(--primary-text-color) 10%, transparent); }
.bkcard .thumb { display: block; width: 100%; aspect-ratio: 1; object-fit: contain; background:
  repeating-conic-gradient(color-mix(in srgb, var(--primary-text-color) 6%, transparent) 0% 25%, transparent 0% 50%) 0 / 20px 20px; cursor: pointer; }
.bkcard .thumb.none { display: flex; align-items: center; justify-content: center; color: var(--secondary-text-color); font-size: .8em; }
.bkcard .meta { padding: 9px 11px; }
.bkcard .meta .t { font-weight: 500; display: flex; align-items: center; gap: 6px; }
.bkcard .meta .s { font-size: .8em; color: var(--secondary-text-color); margin-top: 2px; }
.bkcard .meta .acts { display: flex; gap: 6px; margin-top: 9px; }
.bkcard .meta .acts .btn { flex: 1; justify-content: center; padding: 7px 6px; }
.src { font-size: .68em; text-transform: uppercase; letter-spacing: .04em; padding: 2px 6px; border-radius: 6px;
  background: color-mix(in srgb, var(--primary-text-color) 10%, transparent); color: var(--secondary-text-color); }
button[disabled], select[disabled], input[disabled] { opacity: .5; cursor: default; }
.lightbox { position: fixed; inset: 0; background: rgba(0,0,0,.72); display: flex; align-items: center; justify-content: center; z-index: 9; padding: 20px; }
.lightbox img { max-width: 92vw; max-height: 78vh; border-radius: 10px; background: #1b1b1b; }
.lightbox .lb-info { position: absolute; bottom: 16px; left: 0; right: 0; text-align: center; color: #fff; font-size: .86em; }
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
    this._robotsHtml = null;
    this._booted = true;
    this._update(true);
  }

  _layout() {
    const w = this.shadowRoot && this.shadowRoot.querySelector(".wrap");
    if (w) w.classList.toggle("narrow", !!this._narrow);
  }

  // ---- data ---------------------------------------------------------------------------
  _robots() {
    // The registry's platform survives the robot going unavailable; the integration
    // attribute does not (unavailable entities keep only a few base attributes).
    const reg = this._hass.entities || {};
    return Object.values(this._hass.states).filter((s) => s.entity_id.startsWith("vacuum.") &&
      (reg[s.entity_id] ? reg[s.entity_id].platform === DOMAIN || s.attributes.integration === DOMAIN : s.attributes.integration === DOMAIN));
  }
  _isAdmin() { const u = this._hass && this._hass.user; return !u || u.is_admin !== false; }
  _st(id) { return id ? this._hass.states[id] : undefined; }
  _related(vac) {
    const reg = this._hass.entities || {}, dev = reg[vac] && reg[vac].device_id;
    let ids = dev ? Object.keys(reg).filter((id) => reg[id].device_id === dev) : [];
    if (!ids.length) { const base = vac.split(".")[1]; ids = Object.keys(this._hass.states).filter((id) => id.split(".")[1].startsWith(base)); }
    // What the device's entity ids start with: the vacuum's own, or the device name they were made from.
    const device = dev && this._hass.devices ? this._hass.devices[dev] : null;
    const bases = [objectId(vac), ...(device ? [slug(device.name_by_user), slug(device.name)] : [])].filter(Boolean);
    // By the registry's translation key where the integration sets one, else by the exact end of the
    // entity id ("status" is never "planner_status"), allowing the "_2" Home Assistant adds for a second
    // robot of the same name: <base>_<suffix> first, then the shortest.
    const find = (prefix, suffix, key) => {
      const list = ids.filter((id) => id.startsWith(prefix));
      if (!suffix) return list[0];
      const byKey = key && list.find((id) => reg[id] && reg[id].translation_key === key);
      if (byKey) return byKey;
      const hits = list.filter((id) => new RegExp(`_${suffix}(_\\d+)?$`).test(objectId(id))).sort((a, b) => a.length - b.length);
      return hits.find((id) => bases.some((b) => new RegExp(`^${b}_${suffix}(_\\d+)?$`).test(objectId(id)))) || hits[0];
    };
    // Preset buttons are named "Preset <name>", so their ids are <base>_preset_<name>.
    const isPreset = (id) => (reg[id] && reg[id].translation_key === "preset") || bases.some((b) => objectId(id).startsWith(`${b}_preset_`));
    ids = ids.filter((id) => this._hass.states[id]);   // registry entries without a state (not loaded yet)
    const all = (prefix) => ids.filter((id) => id.startsWith(prefix)).sort();
    return {
      ids, camera: find("camera."), schedules: find("sensor.", "schedules", "schedules"), status: find("sensor.", "status", "status"),
      presets: all("button.").filter(isPreset),
      switches: all("switch."), selects: all("select."), numbers: all("number."), times: all("time."),
      buttons: all("button.").filter((id) => !isPreset(id)),
      totals: { cleans: find("sensor.", "total_cleans"), area: find("sensor.", "total_area_cleaned"), time: find("sensor.", "total_cleaning_time") },
    };
  }
  // An entity's name without the robot's name in front; the entity id when it has no name.
  _label(id) {
    const s = this._st(id), vac = this._st(this._robot), n = String((s && s.attributes.friendly_name) || id);
    const robot = vac && vac.attributes.friendly_name;
    return robot && n.startsWith(robot + " ") ? n.slice(robot.length + 1) : n;
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
    if (!this._robot || !robots.some((r) => r.entity_id === this._robot)) { this._selectRobot(robots[0].entity_id); first = true; }
    const rb = this.shadowRoot.querySelector(".robots");
    const html = robots.length > 1 ? robots.map((r) => `<button data-id="${esc(r.entity_id)}" class="${r.entity_id === this._robot ? "on" : ""}" aria-pressed="${r.entity_id === this._robot ? "true" : "false"}">${esc(r.attributes.friendly_name || r.entity_id)}</button>`).join("") : "";
    // Rebuilding unchanged buttons on every state change would drop keyboard focus.
    if (html !== this._robotsHtml) {
      this._robotsHtml = html; rb.innerHTML = html;
      rb.querySelectorAll("button").forEach((b) => b.onclick = () => { if (b.dataset.id === this._robot) return; this._selectRobot(b.dataset.id); this._update(true); });
    }
    this._renderCard(first);
    this._renderRight(first);
  }

  // Switching robots: stop any driving first (its commands go to the old robot), then start
  // every pane from scratch so nothing from the previous robot carries over.
  _selectRobot(id) {
    this._teardownDrive();
    this._entered = false;
    this._robot = id; this._editing = null; this._records = null; this._recTok = null; this._planOpen = null; this._paneDirty = false;
    this._robotGen = (this._robotGen || 0) + 1;   // replies still in flight for the old robot are dropped
    const pane = this.shadowRoot.querySelector(".pane"); if (pane) pane.innerHTML = "";
  }

  _teardownDrive() {
    if (this._stopDrive) { try { this._stopDrive(); } catch (e) { /* not driving */ } }
    if (this._driveBlur) window.removeEventListener("blur", this._driveBlur);
    this._stopDrive = null; this._driveBlur = null;
  }

  // An input or select in the pane has focus, or the schedule editor is open: a re-render
  // would throw away what the user is typing, so hold it until they are done.
  _formBusy() {
    if (this._tab === "schedules" && this._editing) return true;
    const a = this.shadowRoot && this.shadowRoot.activeElement;
    return !!(a && /^(INPUT|SELECT|TEXTAREA)$/.test(a.tagName) && a.closest(".pane"));
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
    const tabs = [["schedules", "mdi:calendar-clock", "Schedules"], ["planner", "mdi:calendar-check", "Planner"], ["history", "mdi:history", "History"], ["rooms", "mdi:floor-plan", "Rooms"],
                  ["drive", "mdi:gamepad-variant", "Drive"], ["edit", "mdi:pencil-ruler", "Edit map"], ["backups", "mdi:content-save-outline", "Backups"], ["maintenance", "mdi:wrench", "Maintenance"], ["settings", "mdi:tune", "Settings"]];
    if (!right.querySelector(".tabs")) {
      right.innerHTML = `<div class="tabs">${tabs.map(([k, i, l]) => `<button data-tab="${k}"><ha-icon icon="${i}"></ha-icon>${l}</button>`).join("")}</div><div class="pane"></div>`;
      right.querySelectorAll(".tabs button").forEach((b) => b.onclick = () => {
        this._teardownDrive(); this._tab = b.dataset.tab; this._editing = null; this._planOpen = null;
        if (this._tab === "history") this._records = null;   // fetched afresh each time the tab opens
        if (this._tab === "drive") right.querySelector(".pane").innerHTML = "";   // rebuilt with fresh listeners
        this._renderRight(true);
      });
      right.querySelector(".pane").addEventListener("focusout", () => setTimeout(() => {
        if (this._paneDirty && !this._formBusy()) { this._paneDirty = false; this._renderRight(false); }
      }, 0));
    }
    right.querySelectorAll(".tabs button").forEach((b) => b.classList.toggle("on", b.dataset.tab === this._tab));
    const pane = right.querySelector(".pane");
    if (this._tab === "planner") this._ensurePlanSub(); else this._dropPlanSub();
    const sig = JSON.stringify([this._tab, this._robot, this._editing && this._editing.id,
      this._tab === "planner" ? [this._planRev, this._planOpen]
        : this._tab === "edit" ? "edit"   // the editor owns its canvas; don't re-render on map updates
        : this._tab === "backups" ? "backups"   // loads its own data once; don't re-render on map updates
        : this._signature()]);
    if (!first && sig === this._paneSig) return;
    if (!first && this._formBusy()) { this._paneDirty = true; return; }
    this._paneSig = sig; this._paneDirty = false;
    ({ schedules: this._paneSchedules, history: this._paneHistory, rooms: this._paneRooms, drive: this._paneDrive,
       edit: this._paneEdit, backups: this._paneBackups, maintenance: this._paneMaintenance, settings: this._paneSettings, planner: this._panePlanner }[this._tab]).call(this, pane);
  }

  _signature() {
    const r = this._related(this._robot);
    const stable = (a) => Object.keys(a).filter((k) => !VOLATILE.has(k)).sort().map((k) => [k, a[k]]);
    const pick = (ids) => ids.map((id) => { const s = this._st(id); return s ? s.state + JSON.stringify(stable(s.attributes)) : ""; }).join("|");
    // History redraws (and refetches its records) when a clean finishes and the totals move.
    const totals = this._tab === "history" ? [r.totals.cleans, r.totals.area, r.totals.time] : [];
    return pick([this._robot, r.camera, r.schedules, r.status, ...r.switches, ...r.selects, ...r.numbers, ...r.times, ...r.presets, ...totals]);
  }

  // ---- schedules ----------------------------------------------------------------------
  _paneSchedules(pane) {
    const r = this._related(this._robot), list = this._schedules(r), dnd = this._dnd(r);
    if (this._editing) return this._renderEditor(pane, r);
    const rows = list.map((s) => {
      const blocked = s.blocked_by_dnd != null ? s.blocked_by_dnd : inDnd(dnd, s.time);
      const warn = blocked && dnd ? `<div class="warn"><ha-icon icon="mdi:bell-sleep"></ha-icon>Inside ${esc(dndText(dnd))}: the robot will skip it</div>` : "";
      const pr = s.preset_id != null ? this._presets(r).find((p) => p.id === s.preset_id) : null;
      const target = s.preset_id != null ? (pr ? `Preset ${esc(pr.name || s.preset_id)}` : `(deleted preset ${esc(s.preset_id)})`)
        : (s.rooms && s.rooms.length ? esc(s.rooms.join(", ")) : "Whole house");
      // A one-off schedule (made in the app) has no days, only its date.
      const days = (s.days || []).length === 7 ? "Daily" : (s.days || []).length ? s.days.join(" ") : (s.date ? `Once, ${s.date}` : "");
      const levels = [s.suction != null ? FAN[s.suction - 1] : null, s.water_level != null ? `water ${WATER[s.water_level]}` : null, s.clean_passes ? `${s.clean_passes}x` : null].filter(Boolean).join(", ");
      return `<div class="row ${s.enabled ? "" : "off"}" data-id="${esc(s.id)}">
        ${toggle(s.enabled, `${s.time} schedule`, `data-act="toggle" title="${s.enabled ? "Disable" : "Enable"}"`)}
        <div class="main"><div class="t">${esc(s.time)} &middot; ${esc(days)}</div><div class="s">${target}${levels ? " &middot; " + esc(levels) : ""}</div>${warn}</div>
        <button class="icon-btn" data-act="edit" title="Edit"><ha-icon icon="mdi:pencil"></ha-icon></button>
        <button class="icon-btn" data-act="delete" title="${this._isAdmin() ? "Delete" : "Only an administrator can delete schedules"}" ${this._isAdmin() ? "" : "disabled"}><ha-icon icon="mdi:delete"></ha-icon></button>
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
    const presets = this._presets(r), dnd = this._dnd(r);
    // Rooms by id from the map: an unnamed room, or one of two rooms with the same name, cannot be
    // picked by name. Without the map's rooms (not read yet) the vacuum's room names are all there is.
    const geom = ((this._st(r.camera) || { attributes: {} }).attributes.room_geometry || []).filter((g) => g && g.id != null);
    const byId = geom.length > 0;
    const rooms = byId ? geom.map((g) => ({ key: Number(g.id), label: g.name || `Room ${g.id}` }))
      : this._rooms(this._robot).map((n) => ({ key: n, label: n }));
    const picked = byId ? (s.room_ids || []).map(Number) : (s.rooms || []);
    // A room since deleted (a re-map) stays on the schedule until it is taken off it.
    for (const k of picked) if (!rooms.some((x) => x.key === k)) rooms.push({ key: k, label: byId ? `Room ${k} (gone)` : `${k} (gone)` });
    // A one-off schedule (made in the app) has no days; an edit keeps it one-off unless days are picked.
    const oneOff = !isNew && s.repeat === false;
    const state = {
      time: s.time || "09:00", days: new Set((s.days || []).map((d) => d.slice(0, 3))),
      mode: s.preset_id != null ? "preset" : (picked.length || (s.rooms || []).length ? "rooms" : "house"),
      rooms: new Set(picked), preset: s.preset_id != null ? String(s.preset_id) : (presets[0] ? String(presets[0].id) : ""),
      suction: s.suction || 0, water: s.water_level == null ? -1 : s.water_level, passes: s.clean_passes || 0, enabled: s.enabled !== false,
    };
    const dayChips = () => DAYS.map((d) => `<button class="chip ${state.days.has(d) ? "on" : ""}" data-day="${d}">${d}</button>`).join("") +
      `<button class="chip" data-quick="daily">Daily</button><button class="chip" data-quick="weekdays">Weekdays</button><button class="chip" data-quick="weekend">Weekend</button>`;
    const orig = { time: state.time, days: [...state.days].sort().join(), mode: state.mode, rooms: [...state.rooms].sort().join("\n"), preset: state.preset,
                   suction: state.suction, water: state.water, passes: state.passes, enabled: state.enabled };
    // The schedule's own map. A schedule saved on another floor keeps its map: its rooms are not
    // on the current map, so what it cleans can only be changed with the robot on that map.
    const cam = this._st(r.camera), maps = (cam && cam.attributes.maps) || [], curMap = cam ? cam.attributes.map_id : null;
    const own = s.map_id != null ? maps.find((m) => m.id === s.map_id) : null;
    const foreign = !isNew && s.map_id != null && curMap != null && s.map_id !== curMap;
    const ownName = own && own.name && maps.filter((m) => m.name === own.name).length === 1 ? own.name : null;
    // A schedule can point at a preset since deleted on the robot: show it as such, never as another one.
    const presetIds = new Set(presets.map((p) => String(p.id)));
    const deadPreset = state.preset !== "" && !presetIds.has(state.preset);
    // "Robot default" cannot be sent to an existing schedule (an edit sends only what changed, and
    // there is no value that clears a level), so it is offered only where it is already the value.
    const dflt = (cur, none) => (isNew || cur === none ? `<option value="${none}">Robot default</option>` : "");
    const roomChips = () => rooms.map((x, i) => `<button class="chip ${state.rooms.has(x.key) ? "on" : ""}" data-room="${i}">${esc(x.label)}</button>`).join("");
    pane.innerHTML = `<ha-card><div class="card form">
      <h3><span>${isNew ? "New schedule" : `Edit schedule ${esc(s.id)}`}</span></h3>
      <div><label>Start time (robot's time zone)</label><input type="time" value="${esc(state.time)}">
        <div class="warn dnd" hidden><ha-icon icon="mdi:bell-sleep"></ha-icon><span></span></div></div>
      <div><label>Days${oneOff && s.date ? ` (none picked: runs once, ${esc(s.date)})` : ""}</label><div class="chips days">${dayChips()}</div></div>
      <div><label>What to clean</label><div class="seg mode">
        <button data-mode="house" class="${state.mode === "house" ? "on" : ""}" ${foreign ? "disabled" : ""}>Whole house</button>
        <button data-mode="rooms" class="${state.mode === "rooms" ? "on" : ""}" ${foreign ? "disabled" : ""}>Rooms</button>
        <button data-mode="preset" class="${state.mode === "preset" ? "on" : ""}" ${presets.length && !foreign ? "" : "disabled"}>Preset</button></div>
        ${foreign ? `<div class="note">This schedule is for the map ${own && own.name ? `"${esc(own.name)}"` : esc(s.map_id)}, not the one the robot is on. It keeps that map; switch the robot to it to change what it cleans.</div>` : ""}</div>
      <div class="rooms-box" ${state.mode === "rooms" && !foreign ? "" : "hidden"}><div class="chips rooms">${roomChips()}</div></div>
      <div class="preset-box" ${state.mode === "preset" && !foreign ? "" : "hidden"}><select class="preset">${deadPreset ? `<option value="${esc(state.preset)}" selected>(deleted preset ${esc(state.preset)})</option>` : ""}${presets.map((p) => `<option value="${esc(p.id)}" ${String(p.id) === state.preset ? "selected" : ""}>${esc(p.name)}</option>`).join("")}</select></div>
      <div class="grid2">
        <div><label>Suction</label><select class="suction">${dflt(state.suction, 0)}${FAN.map((f, i) => `<option value="${i + 1}" ${state.suction === i + 1 ? "selected" : ""}>${f}</option>`).join("")}</select></div>
        <div><label>Water</label><select class="water">${dflt(state.water, -1)}${WATER.map((w, i) => `<option value="${i}" ${state.water === i ? "selected" : ""}>${w}</option>`).join("")}</select></div>
      </div>
      <div class="grid2">
        <div><label>Passes</label><select class="passes">${dflt(state.passes, 0)}${[1, 2, 3].map((n) => `<option value="${n}" ${state.passes === n ? "selected" : ""}>${n}</option>`).join("")}</select></div>
        <div><label>Enabled</label><button class="switch enabled ${state.enabled ? "on" : ""}" aria-pressed="${state.enabled ? "true" : "false"}" aria-label="Schedule enabled" style="margin-top:6px"></button></div>
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
    q(".rooms").querySelectorAll("[data-room]").forEach((b) => b.onclick = () => { const n = rooms[b.dataset.room].key; state.rooms.has(n) ? state.rooms.delete(n) : state.rooms.add(n); b.classList.toggle("on"); });
    q(".mode").querySelectorAll("button").forEach((b) => b.onclick = () => {
      state.mode = b.dataset.mode; q(".mode").querySelectorAll("button").forEach((o) => o.classList.toggle("on", o === b));
      q(".rooms-box").hidden = state.mode !== "rooms"; q(".preset-box").hidden = state.mode !== "preset";
    });
    q(".enabled").onclick = () => { state.enabled = !state.enabled; q(".enabled").classList.toggle("on", state.enabled); q(".enabled").setAttribute("aria-pressed", String(state.enabled)); };
    q(".preset").onchange = () => { state.preset = q(".preset").value; };
    q(".cancel").onclick = () => { this._editing = null; this._renderRight(true); };
    q(".save").onclick = async () => {
      const err = q(".err"); err.hidden = true;
      const time = q("input[type=time]").value;
      if (!time) { err.textContent = "Pick a start time."; err.hidden = false; return; }
      if (!state.days.size && !oneOff) { err.textContent = "Pick at least one day (the robot only keeps repeating schedules)."; err.hidden = false; return; }
      if (state.mode === "rooms" && !state.rooms.size) { err.textContent = "Pick at least one room."; err.hidden = false; return; }
      const su = Number(q(".suction").value), wa = Number(q(".water").value), pa = Number(q(".passes").value);
      const preset = state.mode === "preset" ? state.preset : "";
      // A new schedule gets everything; an edit sends only what changed, so the rest of the
      // robot's rule (its map above all) is kept as it is.
      const changed = (k, v) => isNew || orig[k] !== v;
      const data = {};
      if (changed("time", time)) data.time = time;
      if (changed("days", [...state.days].sort().join())) data.days = [...state.days];
      if (changed("enabled", state.enabled)) data.enabled = state.enabled;
      const targetChanged = !foreign && (changed("mode", state.mode) || (state.mode === "rooms" && changed("rooms", [...state.rooms].sort().join("\n")))
        || (state.mode === "preset" && changed("preset", preset)));
      if (targetChanged && state.mode === "preset" && !presetIds.has(preset)) { err.textContent = "Pick a preset."; err.hidden = false; return; }
      if (targetChanged) {
        if (state.mode === "rooms") { data[byId ? "room_ids" : "rooms"] = [...state.rooms]; if (ownName) data.map = ownName; }
        else if (state.mode === "preset") data.preset = preset;
        else data.rooms = [];
      }
      if (su && changed("suction", su)) data.suction = FAN[su - 1];
      if (wa >= 0 && changed("water", wa)) data.water = WATER[wa];
      if (pa && changed("passes", pa)) data.passes = pa;
      if (!isNew) {
        if (!Object.keys(data).length) { this._editing = null; this._renderRight(true); return; }
        data.schedule_id = s.id;
      }
      if (state.enabled && (isNew || data.time || data.enabled === true) && dndCheck()) {
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
    // Refetched when the robot finishes a clean (its total moves), and each time the tab opens.
    const robot = this._robot, key = `${robot}|${tot(r.totals.cleans)}`;
    if (!this._records || this._recordsKey !== key) {
      const tok = this._recTok = {};
      let recs = null;
      try {
        const resp = await this._hass.connection.sendMessagePromise({ type: "call_service", domain: DOMAIN, service: "get_clean_records",
          service_data: { entity_id: robot, limit: 100 }, return_response: true });
        recs = (resp && resp.response && resp.response.records) || [];
      } catch (e) { /* recs stays null: said so below, and fetched again on the next redraw */ }
      // A reply for a robot no longer shown, or one a newer request has overtaken, is dropped.
      if (this._recTok !== tok || this._robot !== robot) return;
      if (!recs) {
        this._records = null;
        const runs = pane.querySelector(".runs"); if (runs) runs.innerHTML = `<div class="empty">Could not load history</div>`;
        return;
      }
      this._records = recs; this._recordsFor = robot; this._recordsKey = key;
    }
    const recs = this._records;
    const runs = pane.querySelector(".runs");
    if (!runs) return;     // the tab changed while the records were loading
    runs.innerHTML = recs.length ? recs.slice(0, 20).map((x) => {
      const d = x.started ? new Date(x.started * 1000) : null;
      const when = d ? d.toLocaleDateString(undefined, { weekday: "short", day: "numeric", month: "short" }) + " " + d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" }) : "";
      const meta = [x.area != null ? `${x.area} m²` : null, x.minutes != null ? `${x.minutes} min` : null, START[x.start_type] || null, x.rule_name || null, x.emptied_bin ? "bin emptied" : null].filter(Boolean).join(" · ");
      return `<div class="row"><ha-icon icon="${x.error ? "mdi:alert-circle" : "mdi:robot-vacuum"}" style="color:${x.error ? "var(--error-color,#db4437)" : "var(--primary-color)"}"></ha-icon><div class="main"><div class="t">${esc(when)}</div><div class="s">${esc(meta)}${x.error ? ` · error ${esc(x.error)}` : ""}</div></div></div>`;
    }).join("") : `<div class="empty">No runs recorded yet.</div>`;
    this._chart(pane.querySelector("canvas.days"), this._perDay(recs, 30), (i) => (i % 7 === 0 ? `${29 - i}d` : ""));
    this._chart(pane.querySelector("canvas.weeks"), this._perWeek(recs, 8), (i) => (i === 7 ? "this wk" : `-${7 - i}`));
  }

  _perDay(recs, n) {
    const out = new Array(n).fill(0), now = localDay(Date.now());
    for (const x of recs) { if (!x.started) continue; const d = now - localDay(x.started * 1000); if (d >= 0 && d < n) out[n - 1 - d] += 1; }
    return out;
  }
  _perWeek(recs, n) {
    // Weeks start on Monday, local time (day 0, 1 Jan 1970, was a Thursday).
    const wk = (day) => Math.floor((day + 3) / 7);
    const out = new Array(n).fill(0), now = wk(localDay(Date.now()));
    for (const x of recs) { if (!x.started) continue; const w = now - wk(localDay(x.started * 1000)); if (w >= 0 && w < n) out[n - 1 - w] += x.minutes || 0; }
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
    // The map these room ids belong to: the service refuses them once the robot is on another map.
    const mapId = cam ? cam.attributes.map_id : null;
    const rows = geom.map((g) => {
      const suction = Number(g.suction) || 0, passes = Number(g.passes) || 0;
      // The room's own geometry entry carries its freshness; the name-keyed map is only a fallback
      // (it cannot tell an unnamed room, or two rooms with the same name, apart).
      const f = (g.last_cleaned != null || g.coverage != null ? g : fresh[g.name]) || {}, label = g.name || `Room ${g.id}`, cov = f.coverage || 0, d = f.last_cleaned ? (Date.now() / 1000 - f.last_cleaned) / 86400 : null;
      const cls = d == null ? "bad" : d > 7 ? "warn" : "";
      return `<div class="bar-row ${cls}"><span>${esc(label)}</span><div class="track"><div style="width:${Number(cov) || 0}%"></div></div><span class="r">${esc(ago(f.last_cleaned))}</span></div>
        <div class="actions" style="justify-content:flex-start;margin:-2px 0 6px"><button class="btn" data-room="${esc(g.name)}" data-room-id="${esc(g.id ?? "")}"><ha-icon icon="mdi:play"></ha-icon>Clean ${esc(label)}</button>
        <span class="s" style="font-size:.8em;color:var(--secondary-text-color);align-self:center">${f.coverage != null ? `${esc(f.coverage)}% covered last time` : "not cleaned since the map was made"}${FAN[suction - 1] ? ` · ${FAN[suction - 1]}` : ""}${passes ? ` · ${passes}x` : ""}</span></div>`;
    }).join("");
    pane.innerHTML = `<ha-card><div class="card"><h3><span>Rooms and freshness</span></h3>${rows || `<div class="empty">No rooms on the current map.</div>`}</div></ha-card>`;
    // By id where the map gives one: names cannot pick an unnamed room or one of two same-named rooms.
    pane.querySelectorAll("[data-room]").forEach((b) => b.onclick = () => this._call(DOMAIN, "clean_rooms",
      onMap(b.dataset.roomId !== "" ? { room_ids: [Number(b.dataset.roomId)] } : { rooms: [b.dataset.room] }, mapId), { entity_id: this._robot }));
  }

  // ---- map editor ----------------------------------------------------------------------
  _paneEdit(pane) {
    const FURN = [[1, "Single bed"], [2, "Double bed"], [101, "Sofa"], [103, "Corner sofa"],
      [201, "Table & chairs"], [202, "Table"], [301, "TV unit"], [302, "Wardrobe"],
      [401, "Fridge"], [402, "Washer"], [503, "Plant"], [601, "Toilet"], [701, "Pet house"]];
    this._furnNames = Object.fromEntries(FURN);
    // Carpets and room renaming are read-only for now: carpet writes do not persist
    // standalone, and setAreaInfo "room" can disturb room geometry; both pending safe testing.
    const tools = [["select", "mdi:cursor-move", "Select"], ["forbid", "mdi:cancel", "No-go"],
      ["virtual_wall", "mdi:wall", "Wall"], ["furniture", "mdi:sofa", "Furniture"]];
    pane.innerHTML = `<ha-card><div class="card">
      <div class="etools">${tools.map(([k, i, l]) => `<button class="btn etool" data-tool="${k}"><ha-icon icon="${i}"></ha-icon>${l}</button>`).join("")}
        <select class="efurn" title="Furniture type">${FURN.map(([c, n]) => `<option value="${c}">${n}</option>`).join("")}</select>
        <button class="btn edel" title="Delete selected"><ha-icon icon="mdi:delete"></ha-icon></button></div>
      <div class="ehint">Pick a tool, then draw on the map. Changes are saved to the robot only when you press Save.${this._isAdmin() ? "" : " Only an administrator can save map changes."}</div>
      <div class="estage"><canvas class="ecanvas"></canvas></div>
      <div class="erooms"></div>
      <div class="ebtns">
        <button class="btn eundo"><ha-icon icon="mdi:undo"></ha-icon>Undo</button>
        <button class="btn ecancel"><ha-icon icon="mdi:refresh"></ha-icon>Discard</button>
        <button class="btn primary esave"><ha-icon icon="mdi:content-save"></ha-icon>Save to robot</button>
      </div>
      <div class="s estatus"></div>
    </div></ha-card>`;
    const q = (s) => pane.querySelector(s);
    this._editEl = { canvas: q(".ecanvas"), rooms: q(".erooms"), status: q(".estatus"), furn: q(".efurn") };
    this._edit = { tool: "select", sel: null, areas: null, furniture: [], rooms: [], undo: [], img: null, geom: null, mapId: null };
    pane.querySelectorAll(".etool").forEach((b) => b.onclick = () => {
      this._edit.tool = b.dataset.tool; this._edit.sel = null;
      pane.querySelectorAll(".etool").forEach((x) => x.classList.toggle("on", x === b)); this._editDraw();
    });
    q(".etool").classList.add("on");
    q(".edel").onclick = () => this._editDelete();
    q(".eundo").onclick = () => this._editUndo();
    q(".ecancel").onclick = () => this._editLoad();
    q(".esave").onclick = () => this._editSave();
    if (!this._isAdmin()) { q(".esave").disabled = true; q(".esave").title = "Only an administrator can save map changes"; }
    const c = this._editEl.canvas;
    c.onpointerdown = (e) => this._editDown(e);
    c.onpointermove = (e) => this._editMove(e);
    c.onpointerup = (e) => this._editUp(e);
    // With the pointer captured, a drag released outside the canvas still ends in _editUp; a
    // cancelled pointer (or a capture lost any other way) drops the drag instead of leaving it open.
    c.onpointercancel = c.onlostpointercapture = () => this._editCancel();
    this._editLoad();
  }

  _editGeom() { return this._edit.geom; }
  _editMm2Px(x, y) { const g = this._edit.geom, s = g.scale_px_per_cell, r = g.resolution_mm, [ox, oy] = g.real_origin_mm, gh = g.grid_size[1]; return [((x - ox) / r) * s + s / 2, (gh - 1 - (y - oy) / r) * s + s / 2]; }
  _editPx2Mm(x, y) { const g = this._edit.geom, s = g.scale_px_per_cell, r = g.resolution_mm, [ox, oy] = g.real_origin_mm, gh = g.grid_size[1]; return [Math.round(ox + ((x - s / 2) / s) * r), Math.round(oy + (gh - 1 - (y - s / 2) / s) * r)]; }
  _editPoint(e) {
    const c = this._editEl.canvas, b = c.getBoundingClientRect(), clamp = (v, max) => Math.max(0, Math.min(max, v));
    return [clamp((e.clientX - b.left) / b.width * c.width, c.width), clamp((e.clientY - b.top) / b.height * c.height, c.height)];
  }

  async _editLoad() {
    const r = this._related(this._robot), cam = this._st(r.camera);
    const geom = cam && cam.attributes.map_geometry, src = cam && cam.attributes.entity_picture;
    const tok = this._editTok = {}, el = this._editEl;    // a newer load (or pane) wins
    el.status.textContent = "Loading map...";
    if (!geom || !src) { el.status.textContent = "No map available yet."; return; }
    let res;
    try { res = await this._hass.callWS({ type: "tapo_rv30/map/edit_get", entity_id: this._robot }); }
    catch (err) { if (this._editTok === tok) el.status.textContent = "Could not read the map: " + (err.message || err); return; }
    if (this._editTok !== tok) return;
    const img = new Image();
    img.onerror = () => { if (this._editTok === tok) el.status.textContent = "Could not load the map picture."; };
    img.onload = () => {
      if (this._editTok !== tok) return;
      const c = this._editEl.canvas; c.width = img.naturalWidth; c.height = img.naturalHeight;
      this._edit.img = img; this._edit.geom = geom; this._edit.mapId = res.map_id;
      this._edit.areas = res.areas || {}; this._edit.furniture = res.furniture || []; this._edit.rooms = res.rooms || [];
      this._edit.sel = null; this._edit.undo = [];
      this._editRenderRooms(); this._editDraw();
      this._editEl.status.textContent = "";
    };
    img.src = src.startsWith("http") ? src : this._hass.hassUrl(src);
  }

  _editRenderRooms() {
    const el = this._editEl.rooms;
    if (!this._edit.rooms.length) { el.innerHTML = ""; return; }
    el.innerHTML = `<h5>Rooms</h5>` + this._edit.rooms.map((rm) =>
      `<div class="row"><div class="main"><div class="t">${esc(rm.name || ("Room " + rm.id))}</div></div></div>`).join("") +
      `<div class="ehint">Carpets and room renaming are view-only for now.</div>`;
  }

  _editDraw() {
    const c = this._editEl.canvas, ctx = c.getContext("2d"); if (!this._edit.img) return;
    ctx.clearRect(0, 0, c.width, c.height); ctx.drawImage(this._edit.img, 0, 0);
    const poly = (verts) => { ctx.beginPath(); verts.forEach((p, i) => { const [x, y] = this._editMm2Px(p[0], p[1]); i ? ctx.lineTo(x, y) : ctx.moveTo(x, y); }); };
    const styles = { forbid: ["rgba(219,68,55,.22)", "rgba(219,68,55,.95)"], carpet_rectangle: ["rgba(186,140,90,.30)", "rgba(150,100,55,.95)"], carpet_round: ["rgba(186,140,90,.30)", "rgba(150,100,55,.95)"] };
    for (const t of ["forbid", "carpet_rectangle", "carpet_round"]) for (const [i, a] of (this._edit.areas[t] || []).entries()) {
      poly(a.vertexs); ctx.closePath(); ctx.fillStyle = styles[t][0]; ctx.fill();
      ctx.strokeStyle = styles[t][1]; ctx.lineWidth = this._editSelMatch(t, i) ? 4 : 2; ctx.setLineDash(t === "forbid" ? [] : [6, 4]); ctx.stroke(); ctx.setLineDash([]);
    }
    for (const [i, a] of (this._edit.areas.virtual_wall || []).entries()) {
      poly(a.vertexs); ctx.strokeStyle = "rgba(150,70,210,.95)"; ctx.lineWidth = this._editSelMatch("virtual_wall", i) ? 6 : 4; ctx.stroke();
    }
    for (const [i, f] of (this._edit.furniture || []).entries()) {
      // The robot bakes the furniture picture into the map render, which only refreshes on
      // Save. Fill the box opaquely and label it so the furniture reads as moved straight away.
      poly(f.vertexs); ctx.closePath(); ctx.fillStyle = "rgba(60,90,150,.78)"; ctx.fill();
      ctx.strokeStyle = "rgba(230,238,250,.95)"; ctx.lineWidth = this._editSelMatch("furniture", i) ? 4 : 2; ctx.stroke();
      const cx = f.vertexs.reduce((s, p) => s + p[0], 0) / f.vertexs.length, cy = f.vertexs.reduce((s, p) => s + p[1], 0) / f.vertexs.length;
      const [px, py] = this._editMm2Px(cx, cy); ctx.fillStyle = "#fff"; ctx.font = "11px system-ui, sans-serif"; ctx.textAlign = "center"; ctx.textBaseline = "middle";
      ctx.fillText(this._furnNames?.[f.type] || "Furniture", px, py); ctx.textAlign = "start"; ctx.textBaseline = "alphabetic";
    }
    if (this._edit.drag) { const d = this._edit.drag; ctx.strokeStyle = "rgba(40,110,220,.95)"; ctx.lineWidth = 2; ctx.setLineDash([5, 4]); if (d.line) { ctx.beginPath(); ctx.moveTo(d.x0, d.y0); ctx.lineTo(d.x1, d.y1); ctx.stroke(); } else { ctx.strokeRect(Math.min(d.x0, d.x1), Math.min(d.y0, d.y1), Math.abs(d.x1 - d.x0), Math.abs(d.y1 - d.y0)); } ctx.setLineDash([]); }
  }

  _editSelMatch(kind, i) { const s = this._edit.sel; return s && s.kind === kind && s.i === i; }
  _editSnapshot() { this._edit.undo.push(JSON.stringify({ areas: this._edit.areas, furniture: this._edit.furniture, rooms: this._edit.rooms })); if (this._edit.undo.length > 30) this._edit.undo.shift(); }

  _editReady() { return !!(this._edit && this._edit.img && this._edit.geom && this._edit.areas); }
  _editDown(e) {
    if (!this._editReady()) return;     // nothing to draw on until the map has loaded
    try { this._editEl.canvas.setPointerCapture(e.pointerId); } catch (err) { /* the pointer is already gone */ }
    const [x, y] = this._editPoint(e); const t = this._edit.tool;
    if (t === "select") { this._edit.sel = this._editHit(x, y); if (this._edit.sel) this._edit.moveFrom = this._editPx2Mm(x, y); this._editDraw(); return; }
    if (t === "furniture") { this._editSnapshot(); const [mx, my] = this._editPx2Mm(x, y); const hw = 350, hh = 250; const type = Number(this._editEl.furn.value); this._edit.furniture.push({ type, id: 0, angle: 0, vertexs: [[mx - hw, my - hh], [mx + hw, my - hh], [mx + hw, my + hh], [mx - hw, my + hh]] }); this._edit.sel = { kind: "furniture", i: this._edit.furniture.length - 1 }; this._editDraw(); return; }
    this._edit.drag = { x0: x, y0: y, x1: x, y1: y, line: t === "virtual_wall" };
  }
  _editMove(e) {
    if (!this._editReady()) return;
    const [x, y] = this._editPoint(e);
    if (this._edit.drag) { this._edit.drag.x1 = x; this._edit.drag.y1 = y; this._editDraw(); return; }
    if (this._edit.tool === "select" && this._edit.sel && this._edit.moveFrom && (e.buttons & 1)) {
      const [mx, my] = this._editPx2Mm(x, y); const dx = mx - this._edit.moveFrom[0], dy = my - this._edit.moveFrom[1];
      if (!this._edit.moving) { this._editSnapshot(); this._edit.moving = true; }
      this._edit.moveFrom = [mx, my]; const it = this._editSelItem(); if (it) it.vertexs = it.vertexs.map(([a, b]) => [a + dx, b + dy]); this._editDraw();
    }
  }
  _editUp(e) {
    this._edit.moving = false; this._edit.moveFrom = null;
    if (!this._editReady()) { this._edit.drag = null; return; }
    const d = this._edit.drag; if (!d) return; this._edit.drag = null;
    const moved = Math.hypot(d.x1 - d.x0, d.y1 - d.y0); if (moved < 6) { this._editDraw(); return; }
    const [ax, ay] = this._editPx2Mm(d.x0, d.y0), [bx, by] = this._editPx2Mm(d.x1, d.y1); this._editSnapshot();
    if (this._edit.tool === "virtual_wall") { (this._edit.areas.virtual_wall ||= []).push({ id: 0, vertexs: [[ax, ay], [bx, by]] }); }
    else { const t = this._edit.tool; (this._edit.areas[t] ||= []).push({ id: 0, vertexs: [[ax, ay], [bx, ay], [bx, by], [ax, by]] }); }
    this._editDraw();
  }

  _editCancel() {
    if (!this._edit) return;
    this._edit.moving = false; this._edit.moveFrom = null;
    if (this._edit.drag) { this._edit.drag = null; this._editDraw(); }
  }

  _editHit(x, y) {
    const inside = (verts) => { let hit = false; const pts = verts.map((p) => this._editMm2Px(p[0], p[1])); for (let i = 0, j = pts.length - 1; i < pts.length; j = i++) { const [xi, yi] = pts[i], [xj, yj] = pts[j]; if ((yi > y) !== (yj > y) && x < ((xj - xi) * (y - yi)) / (yj - yi) + xi) hit = !hit; } return hit; };
    const near = (verts) => { const [x0, y0] = this._editMm2Px(verts[0][0], verts[0][1]), [x1, y1] = this._editMm2Px(verts[1][0], verts[1][1]); const L = Math.hypot(x1 - x0, y1 - y0) || 1; return Math.abs((y1 - y0) * x - (x1 - x0) * y + x1 * y0 - y1 * x0) / L < 8; };
    for (const [i, f] of (this._edit.furniture || []).entries()) if (inside(f.vertexs)) return { kind: "furniture", i };
    for (const [i, a] of (this._edit.areas.forbid || []).entries()) if (inside(a.vertexs)) return { kind: "forbid", i };
    for (const [i, a] of (this._edit.areas.virtual_wall || []).entries()) if (near(a.vertexs)) return { kind: "virtual_wall", i };
    return null;
  }
  _editSelItem() { const s = this._edit.sel; if (!s) return null; return s.kind === "furniture" ? this._edit.furniture[s.i] : this._edit.areas[s.kind][s.i]; }
  _editDelete() { const s = this._edit.sel; if (!s || !this._editReady()) return; this._editSnapshot(); if (s.kind === "furniture") this._edit.furniture.splice(s.i, 1); else this._edit.areas[s.kind].splice(s.i, 1); this._edit.sel = null; this._editDraw(); }
  _editUndo() { const u = this._edit.undo.pop(); if (!u) return; const o = JSON.parse(u); this._edit.areas = o.areas; this._edit.furniture = o.furniture; this._edit.rooms = o.rooms; this._edit.sel = null; this._editRenderRooms(); this._editDraw(); }

  async _editSave() {
    // Only the verified-safe layers are written: no-go zones, virtual walls and furniture.
    // Carpets and rooms are left untouched (not sent), so they are preserved as-is.
    if (!this._editReady() || this._edit.mapId == null) { this._editEl.status.textContent = "The map has not loaded yet, so there is nothing to save."; return; }
    if (!this._isAdmin()) { this._editEl.status.textContent = "Only an administrator can save map changes."; return; }
    const payload = { type: "tapo_rv30/map/edit_apply", entity_id: this._robot, map_id: this._edit.mapId,
      areas: { forbid: this._edit.areas.forbid || [], virtual_wall: this._edit.areas.virtual_wall || [] },
      furniture: this._edit.furniture };
    this._editEl.status.textContent = "Saving to robot...";
    try { await this._hass.callWS(payload); this._editEl.status.textContent = "Saved."; this._editLoad(); }
    catch (err) { this._editEl.status.textContent = "Save failed: " + (err.message || err); }
  }

  // ---- maintenance ---------------------------------------------------------------------
  // ---- drive (the app's remote control) ------------------------------------------------
  _paneDrive(pane) {
    const r = this._related(this._robot), vac = this._st(this._robot), st = this._st(r.status);
    const supported = vac.attributes.remote_control !== false;
    const text = st ? st.state : vac.state, remote = text === "Remote Control";
    const sweep = r.switches.find((id) => /sweep_walk|clean_while/.test(id)), sw = sweep ? this._st(sweep) : null;
    // Rebuilt when its stop handlers were torn down (robot or tab switch, or the panel detached),
    // so a held direction always has a blur and stop path back.
    if (!pane.querySelector(".dpad") || !this._stopDrive) {
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
      const q = (s) => pane.querySelector(s), dpad = q(".dpad"), robot = this._robot;
      // Bound to this robot: a robot switch must never redirect a held direction to another one.
      const send = (command) => this._hass.callService(DOMAIN, "remote_drive", { command }, { entity_id: robot }, false, command === "enter");
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
      this._teardownDrive();
      window.addEventListener("blur", stop);
      this._stopDrive = stop; this._driveBlur = stop;
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
      q(".spot").onclick = () => { stop(); this._call("vacuum", "clean_spot", {}, { entity_id: robot }); };
      q(".locate").onclick = () => this._call("vacuum", "locate", {}, { entity_id: robot });
      q(".dock").onclick = async () => { stop(); this._entered = false; try { await send("exit"); } catch (e) { /* not in control */ } this._call("vacuum", "return_to_base", {}, { entity_id: robot }); };
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

  // ---- planner (fed by the integration's websocket subscription) ---------------------------
  async _ensurePlanSub() {
    if (!this.isConnected) return;
    // Subscribed, subscribing, or refused (no retry until the tab is opened again).
    if (this._planFor === this._robot && (this._planUnsub || this._planTok || this._planErr)) return;
    this._dropPlanSub();
    // The token ties the subscription to this request: if the panel disconnects, the tab or
    // the robot changes while subscribing, the late subscription is closed straight away.
    const tok = this._planTok = {}, robot = this._robot;
    this._planFor = robot; this._plan = null; this._planErr = null;
    let unsub;
    try {
      unsub = await this._hass.connection.subscribeMessage((view) => {
        if (this._planTok !== tok) return;
        this._plan = view; this._planRev = (this._planRev || 0) + 1;
        if (this._tab === "planner") this._renderRight(false);
      }, { type: "tapo_rv30/planner/subscribe", entity_id: robot });
    } catch (e) {
      if (this._planTok !== tok) return;
      this._planTok = null;
      this._planErr = (e && e.message) || "The planner needs the integration's 0.20 beta or newer.";
      this._planRev = (this._planRev || 0) + 1; this._renderRight(false);
      return;
    }
    if (this._planTok !== tok) { try { unsub(); } catch (e) { /* already closed */ } return; }
    this._planUnsub = unsub;
  }
  _dropPlanSub() {
    if (this._planUnsub) { try { this._planUnsub(); } catch (e) { /* already closed */ } }
    this._planUnsub = null; this._planFor = null; this._planTok = null;
  }
  connectedCallback() {
    if (!this._booted || !this._hass) return;
    if (this._tab === "planner") this._ensurePlanSub();
    else if (this._tab === "drive") this._update(true);   // the drive pane was emptied on detach: rebuild it with fresh listeners
  }
  disconnectedCallback() {
    this._dropPlanSub();
    this._teardownDrive();   // stops any driving
    if (this._tab === "drive") { const pane = this.shadowRoot.querySelector(".pane"); if (pane) pane.innerHTML = ""; }
  }

  async _planWS(msg) {
    // A reply that lands after a robot switch belongs to the old robot: never draw it under the new one.
    const robot = this._robot, gen = this._robotGen, stale = () => this._robot !== robot || this._robotGen !== gen;
    try {
      const res = await this._hass.callWS({ entity_id: robot, ...msg });
      if (stale()) return res;
      const view = res && (res.view || (res.rooms ? res : null));
      if (view) { this._plan = view; this._planRev = (this._planRev || 0) + 1; this._renderRight(false); }
      return res;
    } catch (e) {
      this.dispatchEvent(new CustomEvent("hass-notification", { detail: { message: (e && e.message) || "The planner refused that" }, bubbles: true, composed: true }));
      // Put the controls back to what the planner really holds, so a refused change does not look saved;
      // while an input is being edited, once focus leaves it (a forgotten signature forces the redraw).
      if (!stale() && this._tab === "planner") {
        if (this._formBusy()) { this._paneSig = null; this._paneDirty = true; } else this._renderRight(true);
      }
      return null;
    }
  }
  _planSet(config) { return this._planWS({ type: "tapo_rv30/planner/set", config }); }
  _planAct(action, extra) { return this._planWS({ type: "tapo_rv30/planner/action", action, ...(extra || {}) }); }

  _panePlanner(pane) {
    const v = this._plan;
    if (this._planErr) { pane.innerHTML = `<ha-card><div class="card"><div class="empty">${esc(this._planErr)}</div></div></ha-card>`; return; }
    if (!v) { pane.innerHTML = `<ha-card><div class="card"><div class="empty">Loading the planner...</div></div></ha-card>`; return; }
    // The planner sends an empty view until the robot's map has been read.
    if (!v.config) { pane.innerHTML = `<ha-card><div class="card"><div class="empty">Waiting for the robot's map. The planner appears once the robot has sent it.</div></div></ha-card>`; return; }
    v.rooms = v.rooms || []; v.people = v.people || []; v.sensors = v.sensors || []; v.due = v.due || []; v.unmapped = v.unmapped || [];
    const admin = this._isAdmin();
    const c = v.config, on = !!c.enabled;
    const targets = (Array.isArray(v.target_choices) ? v.target_choices : [0, 1, 2, 3, 4, 5, 7, 14]).map(Number).filter(Number.isInteger);
    const tname = (n) => (n === 0 ? "Leave out" : n === 1 ? "every day" : n === 7 ? "every week" : n === 14 ? "every 2 weeks" : `every ${n} days`);
    const home = v.people.filter((p) => p.included && p.home).length;
    const pillCls = (st) => (st === "Overdue" ? "over" : st === "Due today" ? "due" : st === "Fresh" ? "fresh" : st === "Left out" ? "out" : "");
    const fresh = (r) => {
      if (!r.target_days) return 0;
      if (!r.last_cleaned) return 100;
      return Math.min(100, Math.round(100 * (Date.now() / 1000 - r.last_cleaned) / 86400 / r.target_days));
    };
    const rooms = v.rooms.map((r) => {
      const listen = r.ignore_occupancy ? "ignores motion" : r.sensors.length ? `listening to ${r.sensors.map((s) => esc(s.name)).join(", ")}` : "no sensors";
      const areas = r.areas.length ? `area ${r.areas.map((a) => esc(a.name)).join(", ")}` : "not linked to an area";
      const inuse = r.in_use_by.length ? ` &middot; <span class="warn" style="display:inline">in use: ${esc(r.in_use_by.join(", "))}</span>` : "";
      let editor = "";
      if (this._planOpen === r.key) {
        const chosen = new Set(r.sensors.map((s) => s.entity_id));
        editor = `<div class="sensors"><div class="chips">${v.sensors.map((s) => `<button class="chip ${chosen.has(s.entity_id) ? "on" : ""}" data-sensor="${esc(s.entity_id)}" data-room="${esc(r.key)}">${esc(s.name)}${s.area ? ` <span style="opacity:.7">(${esc(s.area)})</span>` : ""}</button>`).join("") || `<span class="note">No motion, occupancy or presence sensors in Home Assistant.</span>`}</div>
          <div class="c" style="display:flex;justify-content:space-between;align-items:center;margin-top:10px;font-size:.88em"><span>Ignore motion for this room</span>${toggle(r.ignore_occupancy, `Ignore motion for ${r.name}`, `data-ignore="${esc(r.key)}"`)}</div>
          <p class="note">Sensors from the room's area are picked for you; tap to add others or drop one (a sensor the pets set off, say).</p></div>`;
      }
      return `<div class="proom">
        <div class="nm">${esc(r.name)}</div>
        <div class="fresh-cell"><div class="fbar ${r.score >= 1 ? "due" : ""}"><div style="width:${fresh(r)}%"></div></div><div class="ago">${r.last_cleaned ? esc(ago(r.last_cleaned)) : "not cleaned yet"}</div></div>
        <select data-target="${esc(r.key)}">${targets.map((n) => `<option value="${n}" ${n === r.target_days ? "selected" : ""}>${tname(n)}</option>`).join("")}</select>
        <span class="pill ${pillCls(r.status)}">${esc(r.skipped_today ? "Skipped today" : r.status)}</span>
        <div class="sub"><span>${areas} &middot; ${listen}${inuse}</span><button data-edit="${esc(r.key)}">${this._planOpen === r.key ? "Done" : "Sensors"}</button><button data-skiproom="${esc(r.key)}" data-on="${r.skipped_today ? "0" : "1"}">${r.skipped_today ? "Include today" : "Leave out today"}</button></div>
        ${editor}</div>`;
    }).join("");
    const people = v.people.map((p) => `<button class="chip ${p.included ? "on" : ""}" data-person="${esc(p.entity_id)}">${esc(p.name)}${p.home ? " (home)" : ""}</button>`).join("");
    const opt = (vals, cur, label) => vals.map((n) => `<option value="${n}" ${Number(cur) === n ? "selected" : ""}>${label(n)}</option>`).join("");
    const w = { weekdays: ["", ""], weekends: ["", ""], ...(c.windows || {}) };
    const log = (v.log || []).map((e) => { const d = new Date(e.ts * 1000);
      const when = (Date.now() - d) / 864e5 < 1 && d.getDate() === new Date().getDate() ? d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : d.toLocaleDateString([], { weekday: "short" }) + " " + d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      return `<div class="e"><b>${esc(when)}</b><span>${esc(e.text)}</span></div>`; }).join("");
    pane.innerHTML = `
      <ha-card><div class="card">
        <h3><span>Planner</span>${toggle(on, "Planner", `data-set="enabled"`)}</h3>
        <div class="plan-next">${esc(v.status)}</div>
        ${admin ? "" : `<div class="note" style="margin:0 0 6px">Only an administrator can change the planner.</div>`}
        <div class="plan-sub">${on ? "Keeps each room within its target: it cleans the due rooms when the conditions below allow." : "Turn it on to keep rooms clean by how long ago they were done, instead of fixed times."}</div>
        <div class="chips" style="margin-top:10px">${(v.chips || []).map((t) => `<span class="chip warn">${esc(t)}</span>`).join("")}${v.battery != null ? `<span class="chip info">Battery ${esc(v.battery)}%</span>` : ""}<span class="chip info">${home ? `${home} ${home === 1 ? "person" : "people"} home` : "Nobody home"}</span></div>
        <div class="actions" style="justify-content:flex-start;margin-top:12px;flex-wrap:wrap">
          <button class="btn primary" data-act="clean_now" ${v.due.length ? "" : "disabled"}><ha-icon icon="mdi:play"></ha-icon>Clean due rooms now</button>
          <button class="btn" data-act="skip_today" data-on="${v.skip_today ? "0" : "1"}"><ha-icon icon="mdi:calendar-remove"></ha-icon>${v.skip_today ? "Back on today" : "Skip today"}</button></div>
        <div class="banner" ${c.preview ? "" : "hidden"}><ha-icon icon="mdi:eye-outline"></ha-icon><span class="grow">Preview mode: the planner logs what it would do and never starts the robot. Turn preview off when the log looks right.</span>${toggle(true, "Preview mode", `data-set="preview"`)}</div>
        <div class="banner" ${c.preview ? "hidden" : ""}><ha-icon icon="mdi:robot-vacuum"></ha-icon><span class="grow">The planner starts the robot when rooms are due. Preview mode only logs instead.</span>${toggle(false, "Preview mode", `data-set="preview"`)}</div>
      </div></ha-card>
      ${v.unmapped.length ? `<ha-card><div class="card"><div class="banner" style="margin:0"><ha-icon icon="mdi:link-variant"></ha-icon><span class="grow">Not linked to a Home Assistant area: ${esc(v.unmapped.join(", "))}. Linked rooms use the motion sensors in their area.</span></div>
        <div class="actions" style="justify-content:flex-start;margin-top:10px;flex-wrap:wrap"><button class="btn" data-act="match_areas"><ha-icon icon="mdi:auto-fix"></ha-icon>Match by name</button><button class="btn" data-mapping><ha-icon icon="mdi:cog"></ha-icon>Map rooms to areas</button></div></div></ha-card>` : ""}
      <ha-card><div class="card"><h3><span>Rooms</span><span class="plan-sub">how fresh each room is against its target</span></h3>${rooms || `<div class="empty">No rooms on the current map.</div>`}</div></ha-card>
      <ha-card><div class="card"><h3><span>Only clean when</span></h3><div class="cond">
        <div class="c"><span>Nobody is home<small>${v.people.length ? "tap people to leave someone out" : "no people in Home Assistant"}</small></span>${toggle(c.require_away, "Only clean when nobody is home", `data-set="require_away"`)}</div>
        ${c.require_away && v.people.length ? `<div class="chips people">${people}</div>` : ""}
        <div class="c"><span>Leave out rooms in use<small>motion counts as in use for a while after it stops</small></span><span class="ctl"><select data-num="clear_minutes">${opt([0, 5, 10, 15, 30, 60], c.clear_minutes, (n) => `${n} min`)}</select>${toggle(c.skip_in_use, "Leave out rooms in use", `data-set="skip_in_use"`)}</span></div>
        <div class="c"><span>Battery at least<small>it waits on the dock below this</small></span><select data-num="min_battery">${opt([0, 20, 30, 40, 50, 60, 80], c.min_battery, (n) => (n ? `${n}%` : "any"))}</select></div>
        <div class="c"><span>Not near the robot's own schedules<small>holds off when one starts within the hour</small></span>${toggle(c.avoid_schedules, "Not near the robot's own schedules", `data-set="avoid_schedules"`)}</div>
        <div class="c"><span>Outside Do Not Disturb<small>always: the robot would refuse anyway</small></span><span class="plan-sub">always</span></div>
        <div class="c"><span>Weekdays<small>when it may start</small><small class="err" data-winerr="weekdays" hidden>The end has to be after the start.</small></span><span class="ctl"><input type="time" data-win="weekdays" data-i="0" value="${esc(w.weekdays[0])}"> to <input type="time" data-win="weekdays" data-i="1" value="${esc(w.weekdays[1])}"></span></div>
        <div class="c"><span>Weekends<small class="err" data-winerr="weekends" hidden>The end has to be after the start.</small></span><span class="ctl"><input type="time" data-win="weekends" data-i="0" value="${esc(w.weekends[0])}"> to <input type="time" data-win="weekends" data-i="1" value="${esc(w.weekends[1])}"></span></div>
        <div class="c"><span>If someone comes home mid-run</span><span class="seg" style="min-width:min(220px,100%)"><button data-ret="finish_room" class="${c.on_return === "finish_room" ? "on" : ""}">Finish room, dock</button><button data-ret="keep_going" class="${c.on_return === "keep_going" ? "on" : ""}">Keep going</button></span></div>
        <div class="c"><span>Target for new rooms</span><select data-num="default_target_days">${opt(targets.filter((n) => n), c.default_target_days, tname)}</select></div>
      </div></div></ha-card>
      <ha-card><div class="card log"><h3><span>Recent decisions</span></h3>${log || `<div class="empty">Nothing yet.</div>`}</div></ha-card>`;
    const q = (sel) => pane.querySelectorAll(sel);
    q("[data-set]").forEach((b) => b.onclick = () => this._planSet({ [b.dataset.set]: !c[b.dataset.set] }));
    q("[data-act]").forEach((b) => b.onclick = () => this._planAct(b.dataset.act, b.dataset.on != null ? { on: b.dataset.on === "1" } : {}));
    q("[data-mapping]").forEach((b) => b.onclick = () => this.dispatchEvent(new CustomEvent("hass-more-info", { detail: { entityId: this._robot, view: "settings" }, bubbles: true, composed: true })));
    q("[data-target]").forEach((s) => s.onchange = () => this._planSet({ rooms: { [s.dataset.target]: { target_days: Number(s.value) } } }));
    q("[data-num]").forEach((s) => s.onchange = () => this._planSet({ [s.dataset.num]: Number(s.value) }));
    // A time input fires change on every digit typed, so a window is saved once focus leaves its pair
    // of inputs, never half typed.
    q("[data-win]").forEach((i) => i.onblur = () => {
      const win = i.dataset.win, robot = this._robot, ends = [0, 1].map((n) => pane.querySelector(`[data-win="${win}"][data-i="${n}"]`));
      const pair = ends.map((e) => (e ? e.value : "")), err = pane.querySelector(`[data-winerr="${win}"]`);
      setTimeout(() => {
        if (ends.includes(this.shadowRoot.activeElement) || this._robot !== robot) return;   // still in the pair
        if (err) err.hidden = true;
        // Against what the planner holds now: this pane may not have been redrawn since the last save.
        const held = ((this._plan && this._plan.config && this._plan.config.windows) || {})[win] || w[win];
        if (!pair[0] || !pair[1] || (pair[0] === held[0] && pair[1] === held[1])) return;
        if (pair[0] >= pair[1]) { if (err) err.hidden = false; return; }
        this._planSet({ windows: { [win]: pair } });
      }, 0);
    });
    q("[data-ret]").forEach((b) => b.onclick = () => this._planSet({ on_return: b.dataset.ret }));
    q("[data-edit]").forEach((b) => b.onclick = () => { this._planOpen = this._planOpen === b.dataset.edit ? null : b.dataset.edit; this._renderRight(false); });
    q("[data-skiproom]").forEach((b) => b.onclick = () => this._planAct("skip_room", { room: b.dataset.skiproom, on: b.dataset.on === "1" }));
    q("[data-ignore]").forEach((b) => b.onclick = () => { const r = v.rooms.find((x) => x.key === b.dataset.ignore); this._planSet({ rooms: { [r.key]: { ignore_occupancy: !r.ignore_occupancy } } }); });
    q("[data-person]").forEach((b) => b.onclick = () => {
      const now = v.people.filter((p) => p.included).map((p) => p.entity_id), id = b.dataset.person;
      const next = now.includes(id) ? now.filter((x) => x !== id) : [...now, id];
      this._planSet({ people: next.length === v.people.length ? null : next });
    });
    q("[data-sensor]").forEach((b) => b.onclick = () => {
      const r = v.rooms.find((x) => x.key === b.dataset.room), id = b.dataset.sensor;
      const rc = (c.rooms || {})[r.key] || {}, add = new Set(rc.add_sensors || []), rem = new Set(rc.remove_sensors || []);
      const auto = new Set([...r.sensors.filter((s) => s.auto).map((s) => s.entity_id), ...(r.removed || [])]);
      const chosen = r.sensors.some((s) => s.entity_id === id);
      if (chosen) { if (auto.has(id)) rem.add(id); else add.delete(id); }
      else { if (auto.has(id)) rem.delete(id); else add.add(id); }
      this._planSet({ rooms: { [r.key]: { add_sensors: [...add], remove_sensors: [...rem] } } });
    });
    // Changing the planner needs an administrator (the server refuses anyone else).
    if (!admin) q("button, select, input").forEach((el) => { if (!el.matches("[data-edit], [data-mapping]")) el.disabled = true; });
  }

  // ---- backups -------------------------------------------------------------------------
  _paneBackups(pane) {
    pane.innerHTML = `<ha-card><div class="card">
      <h3><span>Map backups</span>
        <button class="btn bkfetch"><ha-icon icon="mdi:cloud-download"></ha-icon>Fetch from cloud</button></h3>
      <div class="s">Backups held under <code>config/tapo_rv30/map_backups</code>. Tap a map to see it full size, or restore it to the robot (docked and idle). Fetching downloads your latest TP-Link cloud backups so you keep your own copies.</div>
      <div class="s bkstatus" style="margin-top:8px"></div>
      <div class="bkgrid" style="margin-top:12px"><div class="empty">Loading backups...</div></div>
    </div></ha-card>`;
    const grid = pane.querySelector(".bkgrid"), status = pane.querySelector(".bkstatus");
    pane.querySelector(".bkfetch").onclick = () => this._backupFetch(status, grid);
    if (!this._isAdmin()) { pane.querySelector(".bkfetch").disabled = true; status.textContent = "Only an administrator can fetch or restore backups."; }
    this._backupLoad(grid, status);
  }

  async _backupLoad(grid, status) {
    let res;
    try { res = await this._hass.callWS({ type: "tapo_rv30/backups/list", entity_id: this._robot }); }
    catch (e) { grid.innerHTML = `<div class="err">Could not list backups: ${esc(e.message || e)}</div>`; return; }
    const list = res.backups || [];
    this._backups = list;
    if (!list.length) { grid.innerHTML = `<div class="empty">No backups yet. Press "Fetch from cloud" to download your TP-Link map backups.</div>`; return; }
    grid.innerHTML = list.map((b, i) => {
      const f = b.facts || {};
      const sub = [f.extent ? `${f.extent.area_m2} m2` : "", f.room_count ? `${f.room_count} room${f.room_count > 1 ? "s" : ""}` : ""].filter(Boolean).join(" · ");
      const kb = Math.round(b.size / 1024);
      const thumb = b.thumb ? `<img class="thumb" data-i="${i}" src="${esc(b.thumb)}" alt="map preview">` : `<div class="thumb none">No preview</div>`;
      return `<div class="bkcard">${thumb}
        <div class="meta"><div class="t">${esc(b.map_name)} <span class="src">${esc(b.source)}</span></div>
          <div class="s">${esc(b.when)} · ${kb} KB${sub ? " · " + esc(sub) : ""}</div>
          <div class="acts">
            <button class="btn bkview" data-i="${i}"><ha-icon icon="mdi:eye"></ha-icon>View</button>
            <button class="btn primary bkrestore" data-i="${i}"><ha-icon icon="mdi:backup-restore"></ha-icon>Restore</button>
          </div></div></div>`;
    }).join("");
    grid.querySelectorAll(".thumb[data-i], .bkview").forEach((el) => el.onclick = () => this._backupView(list[+el.dataset.i]));
    grid.querySelectorAll(".bkrestore").forEach((el) => { el.onclick = () => this._backupRestore(list[+el.dataset.i], status); el.disabled = !this._isAdmin(); });
  }

  async _backupView(b) {
    const box = document.createElement("div");
    box.className = "lightbox";
    box.innerHTML = `<img src="${esc(b.thumb || "")}"><div class="lb-info">Loading full image...</div>`;
    box.onclick = () => box.remove();
    this.shadowRoot.appendChild(box);
    try {
      const res = await this._hass.callWS({ type: "tapo_rv30/backups/image", entity_id: this._robot, file: b.file });
      if (res.image) box.querySelector("img").src = res.image;
      const f = res.facts || {};
      const bits = [b.map_name, b.when];
      if (f.extent) bits.push(`${f.extent.width_m} × ${f.extent.height_m} m (${f.extent.area_m2} m2)`);
      if (f.room_count) bits.push(`${f.room_count} rooms`);
      box.querySelector(".lb-info").textContent = bits.filter(Boolean).join("   ·   ");
    } catch (e) { box.querySelector(".lb-info").textContent = "Could not load image: " + (e.message || e); }
  }

  _backupRestore(b, status) {
    if (!window.confirm(`Restore "${b.map_name}" from ${b.when}?\n\nThis replaces that map's shape and layout on the robot with this backup. The robot must be docked and idle.`)) return;
    status.textContent = `Restoring "${b.map_name}"...`;
    this._hass.callService(DOMAIN, "restore_map_backup", { map: String(b.map_id), file: b.file, confirm: true }, { entity_id: this._robot }, false, true)
      .then((res) => {
        const r = (res && res.response) ? res.response : res;
        if (r && r.applied) status.textContent = `Restored "${b.map_name}". ${r.next_steps || ""}`;
        else status.textContent = `Restore ended without confirmation: ${r && r.note ? r.note : "check the robot"}.`;
      })
      .catch((e) => { status.textContent = "Restore failed: " + (e.message || e); });
  }

  async _backupFetch(status, grid) {
    status.textContent = "Fetching cloud backups (this can take a moment)...";
    try {
      const res = await this._hass.callService(DOMAIN, "fetch_cloud_map_backups", {}, { entity_id: this._robot }, false, true);
      const r = (res && res.response) ? res.response : res;
      if (r && r.status === "code_sent") {
        status.innerHTML = `TP-Link emailed a verification code. Run the <code>fetch_cloud_map_backups</code> action once with that code, then fetch again.`;
        return;
      }
      const n = (r && r.backups) ? r.backups.length : 0;
      status.textContent = `Fetched ${n} backup${n === 1 ? "" : "s"}.`;
      this._backupLoad(grid, status);
    } catch (e) { status.textContent = "Fetch failed: " + (e.message || e); }
  }

  _paneMaintenance(pane) {
    const r = this._related(this._robot), vac = this._st(this._robot), cons = vac.attributes.consumables || {};
    const bars = Object.entries(cons).map(([k, raw]) => { const v = toNum(raw);
      return `<div class="bar-row ${v <= 10 ? "bad" : v <= 30 ? "warn" : ""}"><span>${esc(k)}</span><div class="track"><div style="width:${Math.max(0, Math.min(100, v))}%"></div></div><span class="r">${v}%</span></div>`; }).join("");
    const btns = r.buttons.map((id) => { const s = this._st(id); return `<button class="btn" data-btn="${esc(id)}"><ha-icon icon="${esc(s.attributes.icon || "mdi:gesture-tap-button")}"></ha-icon>${esc(this._label(id))}</button>`; }).join(" ");
    pane.innerHTML = `<ha-card><div class="card"><h3><span>Consumables</span></h3>${bars || `<div class="empty">No consumable data.</div>`}</div></ha-card>
      <ha-card><div class="card"><h3><span>Actions</span></h3><div class="chips">${btns}</div></div></ha-card>
      <ha-card><div class="card"><h3><span>Map setup</span></h3>
        <div class="s">The map's room names, no-go zones, walls, carpets, furniture, presets and schedules are saved automatically as they change. After a backup restore or a re-map, Restore setup puts back whatever is missing. Save setup takes a snapshot right now.</div>
        <div class="chips" style="margin-top:8px">
          <button class="btn" data-mapsetup="save"><ha-icon icon="mdi:content-save-cog"></ha-icon>Save setup</button>
          <button class="btn" data-mapsetup="apply"><ha-icon icon="mdi:backup-restore"></ha-icon>Restore setup</button>
        </div>
        <div class="s msetup" style="margin-top:8px" hidden></div>
      </div></ha-card>`;
    pane.querySelectorAll("[data-btn]").forEach((b) => b.onclick = () => this._call("button", "press", {}, { entity_id: b.dataset.btn }));
    const status = pane.querySelector(".msetup");
    const counts = (c) => Object.entries(c || {}).map(([k, v]) => `${v} ${k.replace(/_/g, " ")}`).join(", ");
    const run = async (service, data, busyText) => {
      status.hidden = false; status.textContent = busyText;
      try {
        const res = await this._hass.callService(DOMAIN, service, data, { entity_id: this._robot }, false, true);
        const r2 = (res && res.response) ? res.response : res;
        if (service === "save_map_setup") {
          const n = counts(r2.saved); status.textContent = n ? `Saved: ${n}.` : "Saved (nothing on this map to save yet).";
        } else {
          const p = r2.plan || {}, bits = [];
          if ((p.room_names || []).length) bits.push(`${p.room_names.length} room names`);
          Object.entries(p.zones || {}).forEach(([k, v]) => bits.push(`${v} ${k.replace(/_/g, " ")}`));
          if (p.furniture) bits.push(`${p.furniture} furniture`);
          if ((p.presets || []).length) bits.push(`presets: ${p.presets.join(", ")}`);
          if ((p.schedules || []).length) bits.push(`${p.schedules.length} schedule(s)`);
          const skip = (r2.skipped || []).length ? ` Skipped: ${r2.skipped.join("; ")}.` : "";
          status.textContent = (bits.length ? `Put back: ${bits.join(", ")}.` : "Nothing to put back; the map already matches its saved setup.") + skip;
        }
      } catch (e) { status.textContent = "Error: " + (e.message || e); }
    };
    if (!this._isAdmin()) {
      pane.querySelectorAll("[data-mapsetup]").forEach((b) => { b.disabled = true; });
      status.hidden = false; status.textContent = "Only an administrator can save or restore the map setup.";
    }
    pane.querySelector('[data-mapsetup="save"]').onclick = () => run("save_map_setup", {}, "Saving...");
    pane.querySelector('[data-mapsetup="apply"]').onclick = () => {
      if (!window.confirm("Restore the saved map setup? This puts back the saved room names, no-go zones, virtual walls, carpets and furniture on the current map, and recreates any missing presets and schedules.")) return;
      run("apply_map_setup", { confirm: true }, "Restoring...");
    };
  }

  // ---- settings ------------------------------------------------------------------------
  _paneSettings(pane) {
    const r = this._related(this._robot), strip = (id) => this._label(id);
    const sw = r.switches.map((id) => { const s = this._st(id); return `<div class="row"><div class="main"><div class="t">${esc(strip(id))}</div></div>${toggle(s.state === "on", strip(id), `data-sw="${esc(id)}"`)}</div>`; }).join("");
    const sel = r.selects.map((id) => { const s = this._st(id); return `<div class="row"><div class="main"><div class="t">${esc(strip(id))}</div></div><select data-sel="${esc(id)}">${(s.attributes.options || []).map((o) => `<option ${o === s.state ? "selected" : ""}>${esc(o)}</option>`).join("")}</select></div>`; }).join("");
    const num = r.numbers.map((id) => { const s = this._st(id); return `<div class="row"><div class="main"><div class="t">${esc(strip(id))}</div><div class="s">${esc(s.state)} ${esc(s.attributes.unit_of_measurement || "")}</div></div><input type="range" data-num="${esc(id)}" min="${toNum(s.attributes.min)}" max="${toNum(s.attributes.max, 100)}" step="${toNum(s.attributes.step, 1) || 1}" value="${esc(s.state)}"></div>`; }).join("");
    const tim = r.times.map((id) => { const s = this._st(id); return `<div class="row"><div class="main"><div class="t">${esc(strip(id))}</div></div><input type="time" data-time="${esc(id)}" value="${esc(String(s.state).slice(0, 5))}"></div>`; }).join("");
    pane.innerHTML = `<ha-card><div class="card"><h3><span>Settings</span></h3>${sw}${sel}${tim}${num}${(sw || sel || num || tim) ? "" : `<div class="empty">No settings entities.</div>`}</div></ha-card>`;
    pane.querySelectorAll("[data-sw]").forEach((b) => b.onclick = () => this._call("switch", b.classList.contains("on") ? "turn_off" : "turn_on", {}, { entity_id: b.dataset.sw }));
    // A refused change puts the control back to what the entity really holds, so it does not look saved.
    const back = (ok, e, id, text) => { const s = this._st(id); if (!ok && s && e.isConnected) e.value = text(s.state); };
    pane.querySelectorAll("[data-sel]").forEach((e) => e.onchange = async () => back(await this._call("select", "select_option", { option: e.value }, { entity_id: e.dataset.sel }), e, e.dataset.sel, String));
    pane.querySelectorAll("[data-num]").forEach((e) => e.onchange = async () => back(await this._call("number", "set_value", { value: Number(e.value) }, { entity_id: e.dataset.num }), e, e.dataset.num, String));
    // A time input fires change on every digit typed, so a time is saved once focus leaves it, never half typed.
    pane.querySelectorAll("[data-time]").forEach((e) => e.onblur = async () => {
      const id = e.dataset.time, v = e.value, s = this._st(id), hhmm = (x) => String(x).slice(0, 5);
      if (!v || (s && v === hhmm(s.state))) return;
      back(await this._call("time", "set_value", { time: v + ":00" }, { entity_id: id }), e, id, hhmm);
    });
  }
}
if (!customElements.get("tapo-rv30-panel")) customElements.define("tapo-rv30-panel", TapoRV30Panel);
