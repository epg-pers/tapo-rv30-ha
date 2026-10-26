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
// Furniture types offered when the map editor's reply names none (older integration).
const FURN_FALLBACK = [[1, "Single bed"], [2, "Double bed"], [101, "Sofa"], [103, "Corner sofa"],
  [201, "Table & chairs"], [202, "Table"], [301, "TV unit"], [302, "Wardrobe"],
  [401, "Fridge"], [402, "Washer"], [503, "Plant"], [601, "Toilet"], [701, "Pet house"]];
// Size a new furniture item is placed at, in mm: width (across) x depth (the picture's top to bottom).
const FURN_SIZE = { 1: [900, 2000], 2: [1500, 2000], 101: [850, 850], 102: [1600, 900], 103: [2600, 1600],
  201: [2200, 1170], 202: [900, 900], 203: [500, 500], 301: [1600, 450], 302: [1200, 600], 303: [450, 400],
  401: [700, 700], 402: [600, 600], 403: [450, 350], 503: [500, 500], 601: [400, 700], 701: [600, 500], 702: [550, 450], 703: [400, 250] };
const FURN_MIN = 200;     // smallest side a resize allows, mm
// A point of the unturned map picture in the picture turned clockwise by g.rotation, and back
// (the robot stores a display rotation per map, as the Tapo app shows it).
const turnPx = (x, y, g) => {
  const r = g.rotation || 0, W = g.grid_size[0] * g.scale_px_per_cell, H = g.grid_size[1] * g.scale_px_per_cell;
  return r === 90 ? [H - y, x] : r === 180 ? [W - x, H - y] : r === 270 ? [y, W - x] : [x, y];
};
const unturnPx = (x, y, g) => {
  const r = g.rotation || 0, W = g.grid_size[0] * g.scale_px_per_cell, H = g.grid_size[1] * g.scale_px_per_cell;
  return r === 90 ? [y, H - x] : r === 180 ? [W - x, H - y] : r === 270 ? [W - y, x] : [x, y];
};
// A box in world mm (y up) in the robot's corner order: top left, top right, bottom right, bottom left.
const mmBox = (x0, y0, x1, y1) => { const l = Math.min(x0, x1), r = Math.max(x0, x1), b = Math.min(y0, y1), t = Math.max(y0, y1); return [[l, t], [r, t], [r, b], [l, b]]; };
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

// ---- map and preset helpers (plain functions, so the tests can run them) ------------------
// World mm (y up) -> the map picture's px and back, through the map's geometry and its turn.
// Map cell (gx, gy) covers ox + gx * res to ox + (gx + 1) * res (the robot rounds mm down into
// cells), so ox, oy is a cell corner: the bottom left corner of the picture.
const mmToPx = (x, y, g) => { const s = g.scale_px_per_cell, r = g.resolution_mm, [ox, oy] = g.real_origin_mm, gh = g.grid_size[1]; return turnPx(((x - ox) / r) * s, (gh - (y - oy) / r) * s, g); };
const pxToMm = (px, py, g) => { const s = g.scale_px_per_cell, r = g.resolution_mm, [ox, oy] = g.real_origin_mm, gh = g.grid_size[1]; const [x, y] = unturnPx(px, py, g); return [Math.round(ox + (x / s) * r), Math.round(oy + (gh - y / s) * r)]; };
// A polygon's area (shoelace), in the square of its units; and whether a point is inside it.
const polyArea = (verts) => { const v = verts || []; let s = 0; for (let i = 0, j = v.length - 1; i < v.length; j = i++) s += v[j][0] * v[i][1] - v[i][0] * v[j][1]; return Math.abs(s) / 2; };
const inPoly = (x, y, pts) => { let hit = false; for (let i = 0, j = pts.length - 1; i < pts.length; j = i++) { const [xi, yi] = pts[i], [xj, yj] = pts[j]; if ((yi > y) !== (yj > y) && x < ((xj - xi) * (y - yi)) / (yj - yi) + xi) hit = !hit; } return hit; };
// A point inside a room's outline for its badge: the centroid, or for a room shaped so that the
// centroid falls outside it (an L, a U), the middle of the widest span across it at that height.
const polyLabel = (verts) => {
  const n = verts.length; let a = 0, cx = 0, cy = 0;
  for (let i = 0, j = n - 1; i < n; j = i++) {
    const f = verts[j][0] * verts[i][1] - verts[i][0] * verts[j][1];
    a += f; cx += (verts[j][0] + verts[i][0]) * f; cy += (verts[j][1] + verts[i][1]) * f;
  }
  if (!a) return [verts.reduce((s, p) => s + p[0], 0) / n, verts.reduce((s, p) => s + p[1], 0) / n];
  cx /= 3 * a; cy /= 3 * a;
  if (inPoly(cx, cy, verts)) return [cx, cy];
  const xs = [];
  for (let i = 0, j = n - 1; i < n; j = i++) { const [xi, yi] = verts[i], [xj, yj] = verts[j]; if ((yi > cy) !== (yj > cy)) xs.push(xi + ((cy - yi) * (xj - xi)) / (yj - yi)); }
  xs.sort((p, q) => p - q);
  let best = null;
  for (let k = 0; k + 1 < xs.length; k += 2) if (!best || xs[k + 1] - xs[k] > best[1] - best[0]) best = [xs[k], xs[k + 1]];
  return best ? [(best[0] + best[1]) / 2, cy] : [cx, cy];
};
// A copy of a list with one item moved from one place to another (the cleaning order).
const moveItem = (list, from, to) => {
  const out = list.slice();
  if (from < 0 || from >= out.length) return out;
  const [it] = out.splice(from, 1);
  out.splice(Math.max(0, Math.min(out.length, to)), 0, it);
  return out;
};
// Names compared as the integration compares them: accents and case ignored, ends trimmed.
const foldName = (s) => String(s ?? "").normalize("NFKD").replace(/[\u0300-\u036f]/g, "").trim().toLowerCase();
// "<name> copy", or "<name> copy 2", 3... when that is taken on the map, cut to max characters
// with the suffix kept.
const uniqueCopyName = (name, taken, max = 40) => {
  const used = new Set([...(taken || [])].map(foldName)), base = String(name ?? "").trim();
  for (let n = 1; ; n++) {
    const suffix = n === 1 ? " copy" : ` copy ${n}`, cand = base.slice(0, max - suffix.length).trimEnd() + suffix;
    if (!used.has(foldName(cand))) return cand;
  }
};
// The robot's own pace from its past cleans, in m2 per minute: total area over total time of the
// runs with an area and at least 5 minutes (shorter ones are mostly a start and a stop). The
// map's own runs when it has a few (floors differ), else all of them. null with nothing to go on.
const cleanPace = (runs, mapId) => {
  const ok = (runs || []).filter((x) => Number(x.area) > 0 && Number(x.minutes) >= 5);
  const own = ok.filter((x) => mapId != null && x.map_id === mapId), use = own.length >= 3 ? own : ok;
  if (!use.length) return null;
  const area = use.reduce((s, x) => s + Number(x.area), 0), min = use.reduce((s, x) => s + Number(x.minutes), 0);
  return { perMin: area / min, runs: use.length };
};
// What a preset cleans: rooms [{id, passes}] with sizes {id: m2} -> the area with every pass
// counted, how many rooms have no known size, and minutes at the robot's pace (null without one).
const presetEstimate = (rooms, areas, runs, mapId) => {
  let m2 = 0, unknown = 0;
  for (const rm of rooms || []) { const a = Number((areas || {})[rm.id]); if (a > 0) m2 += a * (Number(rm.passes) || 1); else unknown++; }
  const pace = cleanPace(runs, mapId);
  return { m2, unknown, minutes: pace && m2 > 0 ? Math.max(1, Math.round(m2 / pace.perMin)) : null, runs: pace ? pace.runs : 0 };
};
// A preset's levels in a few words: each level once, in the order its rooms use them.
const levelSummary = (rooms) => {
  const uniq = (f) => [...new Set((rooms || []).map(f).filter((v) => v != null))];
  const su = uniq((x) => FAN[x.suction - 1]), wa = uniq((x) => WATER[x.water]), pa = uniq((x) => (x.passes ? `${x.passes}x` : null));
  return [su.join("/"), wa.length ? `water ${wa.join("/")}` : "", pa.join("/")].filter(Boolean).join(", ");
};
// Suction levels to offer: the four the robot uses, and Ultra (5) only where a preset already has it.
const fanLevels = (presets) => ((presets || []).some((p) => (p.rooms || []).some((x) => Number(x.suction) === 5)) ? [1, 2, 3, 4, 5] : [1, 2, 3, 4]);

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
.maprow { flex-wrap: wrap; }
.maprow .main { flex: 1 1 100%; }
.maprow .pending { display: flex; align-items: center; gap: 10px; width: 100%; margin-top: 6px; font-size: .86em; color: var(--secondary-text-color); }
.ibar { position: relative; flex: 1; height: 4px; border-radius: 2px; overflow: hidden; background: color-mix(in srgb, var(--primary-text-color) 12%, transparent); }
.ibar::after { content: ""; position: absolute; top: 0; bottom: 0; width: 35%; border-radius: 2px; background: var(--primary-color); animation: tapo-slide 1.1s ease-in-out infinite; }
@keyframes tapo-slide { from { left: -35%; } to { left: 100%; } }
.btn.busy { opacity: .75; }
.maprow .mapacts { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; justify-content: flex-end; width: 100%; margin-top: 6px; }
.emaps { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; margin-bottom: 8px; }
.emaps select { flex: 1; min-width: 140px; }
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
.keep { font-size: .8em; font-weight: 400; color: var(--secondary-text-color); display: inline-flex; align-items: center; gap: 6px; }
.keep select { padding: 5px 8px; border-radius: 8px; border: 1px solid color-mix(in srgb, var(--primary-text-color) 20%, transparent);
  background: var(--card-background-color); color: var(--primary-text-color); font: inherit; }
.keepnote { font-size: .8em; color: var(--secondary-text-color); margin: -4px 0 6px; }
.runmap { padding: 4px 0 12px; border-bottom: 1px solid color-mix(in srgb, var(--primary-text-color) 10%, transparent); }
.runmap .runimg { display: block; max-width: 100%; max-height: 420px; margin: 0 auto 8px; border-radius: 10px; }
.runmap .acts { display: flex; gap: 8px; justify-content: center; }
.runmap a.btn { text-decoration: none; }
.mapbtn { flex: none; padding: 7px 10px; }
input.rename { width: 100%; box-sizing: border-box; padding: 8px 10px; border-radius: 8px; font: inherit; margin-bottom: 4px;
  border: 1px solid color-mix(in srgb, var(--primary-text-color) 20%, transparent); background: var(--card-background-color); color: var(--primary-text-color); }
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
.bkcard .restore-opts { margin-top: 9px; display: grid; gap: 6px; font-size: .86em; }
.jobbar { margin-top: 8px; }
.jobbar .track { height: 8px; border-radius: 4px; overflow: hidden; background: color-mix(in srgb, var(--primary-text-color) 12%, transparent); }
.jobbar .fill { height: 100%; width: 0; background: var(--primary-color); border-radius: 4px; transition: width .6s ease; }
.jobbar.bad .fill { background: var(--error-color, #db4437); }
.jobbar .lbl { font-size: .8em; color: var(--secondary-text-color); margin-top: 4px; display: flex; justify-content: space-between; gap: 8px; }
.bkcard .restore-opts label { display: flex; align-items: center; gap: 6px; cursor: pointer; }
.bkcard .restore-opts label.off { opacity: .5; cursor: default; }
.bkcard .restore-opts input.rename { margin: 0; }
.src { font-size: .68em; text-transform: uppercase; letter-spacing: .04em; padding: 2px 6px; border-radius: 6px;
  background: color-mix(in srgb, var(--primary-text-color) 10%, transparent); color: var(--secondary-text-color); }
button[disabled], select[disabled], input[disabled] { opacity: .5; cursor: default; }
.lightbox { position: fixed; inset: 0; background: rgba(0,0,0,.72); display: flex; align-items: center; justify-content: center; z-index: 9; padding: 20px; }
.lightbox img { max-width: 92vw; max-height: 78vh; border-radius: 10px; background: #1b1b1b; }
.lightbox .lb-info { position: absolute; bottom: 16px; left: 0; right: 0; text-align: center; color: #fff; font-size: .86em; }
.pnew { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; justify-content: flex-end; }
.pnew select, .pk select { padding: 7px 8px; border-radius: 10px; border: 1px solid color-mix(in srgb, var(--primary-text-color) 20%, transparent);
  background: var(--card-background-color); color: var(--primary-text-color); font: inherit; font-size: .88em; min-width: 0; }
.prow { flex-wrap: wrap; }
.prow .main { flex: 1 1 220px; }
.prow .pacts { display: flex; align-items: center; gap: 2px; margin-left: auto; }
.prow .pacts .btn { padding: 7px 12px; margin-right: 4px; }
.pgrp { display: flex; align-items: center; gap: 8px; }
.pstage { position: relative; }
.pcanvas { width: 100%; height: auto; display: block; cursor: pointer; }
.pk { display: grid; grid-template-columns: 26px 26px minmax(80px, 1fr) minmax(250px, 340px) 96px; gap: 6px 8px; align-items: center; padding: 6px 0;
  border-bottom: 1px solid color-mix(in srgb, var(--primary-text-color) 10%, transparent); font-size: .92em; }
.pk:last-child { border-bottom: none; }
.pk .grip { display: flex; align-items: center; justify-content: center; height: 32px; cursor: grab; touch-action: none; color: var(--secondary-text-color); }
.pk .grip ha-icon { --mdc-icon-size: 20px; pointer-events: none; }
.pk .num { width: 24px; height: 24px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: .8em; font-weight: 500;
  background: var(--primary-color); color: var(--text-primary-color, #fff); }
.pk .nm { font-weight: 500; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.pk .nm small { font-weight: 400; color: var(--warning-color, #ff9800); }
.pk .lv { display: grid; grid-template-columns: 1fr 1.3fr 1fr; gap: 6px; }
.pk select { padding: 6px 4px; border-radius: 8px; width: 100%; }
.pk select.unset { border-color: var(--warning-color, #ff9800); box-shadow: 0 0 0 1px var(--warning-color, #ff9800); }
.pk .ord { display: flex; }
.pk .ord .icon-btn { width: 32px; height: 32px; }
.pk.all .nm { font-weight: 400; color: var(--secondary-text-color); }
.pk.dragging { box-shadow: 0 2px 10px rgba(0,0,0,.35); border-radius: 10px; position: relative; z-index: 1;
  background: color-mix(in srgb, var(--primary-color) 14%, var(--card-background-color, #fff)); }
/* Picked rooms on two lines in a narrow pane: the page's narrow layout, or a pane under 600 px wide
   (Home Assistant only sets narrow at 870 px and below, and the one-line rows need about 510 px). */
.pane { container-type: inline-size; }
.wrap.narrow .pk { grid-template-columns: 26px 26px minmax(0, 1fr) 96px; }
.wrap.narrow .pk .grip { grid-row: 1 / span 2; grid-column: 1; }
.wrap.narrow .pk .num { grid-row: 1; grid-column: 2; }
.wrap.narrow .pk .nm { grid-row: 1; grid-column: 3; }
.wrap.narrow .pk .ord { grid-row: 1; grid-column: 4; }
.wrap.narrow .pk .lv { grid-row: 2; grid-column: 2 / -1; }
@container (max-width: 600px) {
  .pk { grid-template-columns: 26px 26px minmax(0, 1fr) 96px; }
  .pk .grip { grid-row: 1 / span 2; grid-column: 1; }
  .pk .num { grid-row: 1; grid-column: 2; }
  .pk .nm { grid-row: 1; grid-column: 3; }
  .pk .ord { grid-row: 1; grid-column: 4; }
  .pk .lv { grid-row: 2; grid-column: 2 / -1; }
}
.wrap.narrow .prow .pacts { width: 100%; justify-content: flex-end; }
`;

class TapoRV30Panel extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: "open" });
    this._tab = "schedules";
    this._robot = null;
    this._editing = null;      // schedule being edited (object) or {} for new, or null
    this._preEdit = null;      // preset being edited or made (the editor's working copy), or null
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
      history: find("select.", "clean_map_history"),
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
    this._robot = id; this._editing = null; this._records = null; this._hist = null; this._recTok = null; this._planOpen = null; this._paneDirty = false;
    this._pre = null; this._preKey = null; this._preTok = null; this._preEdit = null; this._preMaps = null; this._preHist = null;
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
    if (this._tab === "presets" && this._preEdit) return true;     // the preset editor, likewise
    // A map row being renamed, copied or deleted (and its progress bar) is not redrawn under the user.
    if (this._tab === "settings" && this.shadowRoot.querySelector(".maprow input.rename, .maprow [data-act]")) return true;
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
    const tabs = [["schedules", "mdi:calendar-clock", "Schedules"], ["presets", "mdi:play-box-multiple", "Presets"], ["planner", "mdi:calendar-check", "Planner"], ["history", "mdi:history", "History"], ["rooms", "mdi:floor-plan", "Rooms"],
                  ["drive", "mdi:gamepad-variant", "Drive"], ["edit", "mdi:pencil-ruler", "Edit map"], ["backups", "mdi:content-save-outline", "Backups"], ["maintenance", "mdi:wrench", "Maintenance"], ["settings", "mdi:tune", "Settings"]];
    if (!right.querySelector(".tabs")) {
      right.innerHTML = `<div class="tabs">${tabs.map(([k, i, l]) => `<button data-tab="${k}"><ha-icon icon="${i}"></ha-icon>${l}</button>`).join("")}</div><div class="pane"></div>`;
      right.querySelectorAll(".tabs button").forEach((b) => b.onclick = () => {
        this._teardownDrive(); this._tab = b.dataset.tab; this._editing = null; this._planOpen = null; this._preEdit = null;
        if (this._tab === "history") this._records = null;   // fetched afresh each time the tab opens
        if (this._tab === "presets") { this._preKey = null; this._preMaps = null; this._preHist = null; }   // likewise
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
        // Presets: a list arrived (_preRev) or the preset buttons changed; not every status change.
        : this._tab === "presets" ? [this._preRev, this._presetKey(this._related(this._robot))]
        : this._tab === "edit" ? "edit"   // the editor owns its canvas; don't re-render on map updates
        : this._tab === "backups" ? "backups"   // loads its own data once; don't re-render on map updates
        : this._signature()]);
    if (!first && sig === this._paneSig) return;
    if (!first && this._formBusy()) { this._paneDirty = true; return; }
    this._paneSig = sig; this._paneDirty = false;
    ({ schedules: this._paneSchedules, presets: this._panePresets, history: this._paneHistory, rooms: this._paneRooms, drive: this._paneDrive,
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
    const dnd = this._dnd(r);
    // Presets by map and id (ids repeat across maps): from the Presets tab's list when it has been
    // read for this robot, with their real names and maps; else from the preset buttons (ids only).
    // The Presets tab's list, only while it is current (a preset made in the app since would be missing).
    const listed = this._pre && this._pre.for === this._robot && this._pre.data && this._preKey === this._presetKey(r) ? this._pre.data : null;
    const pkey = (mapId, id) => (mapId != null ? `${mapId}:${id}` : String(id));
    const presets = listed ? listed.presets.map((p) => ({ key: pkey(p.map_id, p.id), id: p.id, map_id: p.map_id, name: p.name }))
      : this._presets(r).map((p) => ({ key: String(p.id), id: p.id, map_id: null, name: p.name }));
    // The schedule's preset: by its map and id where both are known, else the one preset with that id.
    const presetKey = () => {
      if (s.preset_id == null) return presets[0] ? presets[0].key : "";
      const hits = presets.filter((p) => String(p.id) === String(s.preset_id) && (s.map_id == null || p.map_id == null || p.map_id === s.map_id));
      return hits.length ? hits[0].key : pkey(s.map_id, s.preset_id);
    };
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
      rooms: new Set(picked), preset: presetKey(),
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
    const presetIds = new Set(presets.map((p) => p.key));
    const deadPreset = state.preset !== "" && !presetIds.has(state.preset);
    // Grouped by map when the presets span more than one (the same name can be on two floors).
    const presetOpt = (p) => `<option value="${esc(p.key)}" ${p.key === state.preset ? "selected" : ""}>${esc(p.name)}</option>`;
    const presetMaps = [...new Set(presets.map((p) => p.map_id))];
    const presetOpts = () => (listed && presetMaps.length > 1
      ? presetMaps.map((m) => { const mp = listed.maps.find((x) => x.id === m);
        return `<optgroup label="${esc((mp && mp.name) || `Map ${m}`)}">${presets.filter((p) => p.map_id === m).map(presetOpt).join("")}</optgroup>`; }).join("")
      : presets.map(presetOpt).join(""));
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
      <div class="preset-box" ${state.mode === "preset" && !foreign ? "" : "hidden"}><select class="preset">${deadPreset ? `<option value="${esc(state.preset)}" selected>(deleted preset ${esc(state.preset.split(":").pop())})</option>` : ""}${presetOpts()}</select></div>
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
        // A new schedule's rooms are the current map's (its map_id is only a preset's, handed over
        // from the Presets tab), so only an edit names the schedule's own map.
        if (state.mode === "rooms") { data[byId ? "room_ids" : "rooms"] = [...state.rooms]; if (ownName && !isNew) data.map = ownName; }
        else if (state.mode === "preset") {
          // The preset's id, and its map where known: the same id can be a different preset on another map.
          const pr = presets.find((p) => p.key === preset), mapId = pr && pr.map_id != null ? pr.map_id : s.map_id;
          data.preset = pr ? pr.id : Number(preset.split(":").pop());
          if (mapId != null) data.map = String(mapId);
        }
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

  // ---- presets (the robot's own "customisation rules", as the Tapo app edits them) ------
  // The list comes from the integration (preset/list): every map's presets with their rooms in
  // cleaning order, their levels and the schedules that run them. It is read when the tab opens,
  // after a change made here and when the robot's preset buttons change; never on every update.
  _presetKey(r) { return JSON.stringify(r.presets.map((id) => { const s = this._st(id); return s ? [id, s.attributes] : [id]; })); }

  async _presetFetch(key) {
    const robot = this._robot, tok = this._preTok = {};
    this._preKey = key;
    let data = null, err = null;
    try { data = await this._hass.callWS({ type: `${DOMAIN}/preset/list`, entity_id: robot }); }
    catch (e) { err = (e && e.message) || "Could not read the presets"; }
    if (this._preTok !== tok || this._robot !== robot) return;    // a newer request, or another robot
    this._preTok = null;
    this._pre = { for: robot, err, data: data && { maps: data.maps || [], presets: data.presets || [] } };
    this._preRev = (this._preRev || 0) + 1;
    if (this._tab === "presets") this._renderRight(false);
  }

  // The robot's past cleans (for the editor's time estimate), read once per visit to the tab.
  _presetRuns() {
    const robot = this._robot;
    if (!this._preHist || this._preHist.for !== robot) {
      this._preHist = { for: robot, runs: this._hass.callWS({ type: `${DOMAIN}/history/list`, entity_id: robot }).then((h) => (h && h.runs) || [], () => []) };
    }
    return this._preHist.runs;
  }

  // A saved map's picture, geometry, rooms and room-id grid (any map, not just the current one),
  // with the pictures loaded. Kept for the visit to the tab; a failed read is tried again next time.
  _presetMap(mapId) {
    const key = `${this._robot}|${mapId}`;
    this._preMaps = this._preMaps || {};
    if (!this._preMaps[key]) {
      const load = (src) => new Promise((done) => {
        if (!src) { done(null); return; }
        const img = new Image();
        img.onload = () => done(img); img.onerror = () => done(null);
        img.src = src;
      });
      this._preMaps[key] = this._hass.callWS({ type: `${DOMAIN}/map/edit_get`, entity_id: this._robot, map_id: mapId, picture: true })
        .then(async (res) => {
          if (!res || !res.picture || !res.geometry) return { res: res || {}, img: null, mask: null };
          const [img, mask] = await Promise.all([load(res.picture), load(res.room_mask)]);
          return { res, img, mask };
        })
        .catch((e) => { if (this._preMaps) delete this._preMaps[key]; throw e; });
    }
    return this._preMaps[key];
  }

  _panePresets(pane) {
    const r = this._related(this._robot);
    if (this._preEdit) return this._renderPresetEditor(pane, r);
    const key = this._presetKey(r);
    if (this._preKey !== key) this._presetFetch(key);
    const pre = this._pre && this._pre.for === this._robot ? this._pre : null;
    const shell = (body) => `<ha-card><div class="card"><h3><span>Presets</span></h3>${body}</div></ha-card>`;
    if (!pre) { pane.innerHTML = shell(`<div class="empty">Loading presets...</div>`); return; }
    if (!pre.data) { pane.innerHTML = shell(`<div class="err">${esc(pre.err)}</div>`); return; }
    const { maps, presets } = pre.data, admin = this._isAdmin();
    // The current map first, then the others in the robot's order; a preset on a map the list
    // does not name still shows, under its map id.
    // A map not saved yet (being made) shows only if it somehow has presets.
    const groups = maps.filter((m) => m.saved !== false || presets.some((p) => p.map_id === m.id)).sort((a, b) => (b.current ? 1 : 0) - (a.current ? 1 : 0));
    for (const p of presets) if (!groups.some((m) => m.id === p.map_id)) groups.push({ id: p.map_id, name: null });
    const mapName = (m) => m.name || `Map ${m.id}`;
    const days = (d) => ((d || []).length === 7 ? "Daily" : (d || []).join(" "));
    const when = (s) => `${s.time}${(s.days || []).length ? " " + days(s.days) : ""}`;
    const row = (p) => {
      const i = presets.indexOf(p), rooms = p.rooms || [], sch = p.schedules || [];
      // In order: an arrow between the rooms; otherwise the robot picks its own way round.
      const names = rooms.map((x) => esc(x.name || `Room ${x.id}`)).join(p.clean_order ? " &rarr; " : ", ");
      const levels = levelSummary(rooms);
      const used = sch.length ? `<span title="${esc(sch.map(when).join(", "))}">${sch.length} schedule${sch.length === 1 ? "" : "s"}</span>` : "no schedules";
      return `<div class="row prow" data-i="${i}">
        <div class="main"><div class="t">${esc(p.name)}${p.clean_order ? ` <span class="src">in order</span>` : ""}</div>
          <div class="s">${names || "No rooms"}</div>
          <div class="s">${levels ? esc(levels) + " &middot; " : ""}${used}</div>
          ${p.valid === false ? `<div class="warn"><ha-icon icon="mdi:alert-outline"></ha-icon>The robot marks this preset as broken (a room in it has gone). Edit it to fix it.</div>` : ""}</div>
        <div class="pacts">
          <button class="btn primary" data-act="run" aria-label="Run ${esc(p.name)}"><ha-icon icon="mdi:play"></ha-icon>Run</button>
          <button class="icon-btn" data-act="edit" title="Edit" aria-label="Edit ${esc(p.name)}"><ha-icon icon="mdi:pencil"></ha-icon></button>
          <button class="icon-btn" data-act="dup" title="Duplicate" aria-label="Duplicate ${esc(p.name)}"><ha-icon icon="mdi:content-copy"></ha-icon></button>
          <button class="icon-btn" data-act="sched" title="Add a schedule that runs it" aria-label="Schedule ${esc(p.name)}"><ha-icon icon="mdi:calendar-plus"></ha-icon></button>
          <button class="icon-btn" data-act="del" title="${admin ? "Delete" : "Only an administrator can delete presets"}" aria-label="Delete ${esc(p.name)}" ${admin ? "" : "disabled"}><ha-icon icon="mdi:delete"></ha-icon></button>
        </div></div>`;
    };
    const body = groups.map((m) => {
      const mine = presets.filter((p) => p.map_id === m.id);
      return `<h5>${esc(mapName(m))}${m.current ? " (current map)" : ""}</h5>${mine.map(row).join("") || `<div class="s" style="padding:4px 0 8px">No presets on this map yet.</div>`}`;
    }).join("");
    // New presets go on saved maps only (a map being made is not one yet).
    const saved = maps.filter((m) => m.saved !== false), cur = saved.find((m) => m.current) || saved[0];
    const picker = saved.length > 1 ? `<select class="pmap" aria-label="Map for the new preset">${groups.filter((m) => saved.includes(m)).map((m) => `<option value="${esc(m.id)}" ${m === cur ? "selected" : ""}>${esc(mapName(m))}</option>`).join("")}</select>` : "";
    pane.innerHTML = `<ha-card><div class="card">
      <h3><span>Presets</span><span class="pnew">${picker}<button class="btn primary" data-act="new" ${cur ? "" : "disabled"}><ha-icon icon="mdi:plus"></ha-icon>New preset</button></span></h3>
      ${presets.length || maps.length ? body : `<div class="empty">No presets yet. A preset is a set of rooms with their own levels, run from here, the app, a schedule or its button.</div>`}
    </div></ha-card>`;
    const newBtn = pane.querySelector('[data-act="new"]');
    newBtn.onclick = () => {
      const sel = pane.querySelector(".pmap"), mapId = sel ? Number(sel.value) : cur.id;
      this._presetOpen({ map_id: mapId, name: "", clean_order: true, rooms: [] }, "New preset");
    };
    pane.querySelectorAll(".prow").forEach((el) => {
      const p = presets[Number(el.dataset.i)], act = (a) => el.querySelector(`[data-act="${a}"]`);
      act("run").onclick = () => {
        if (!confirm(`Start ${p.name} now? The robot will leave the dock.`)) return;
        this._call(DOMAIN, "run_preset", { preset: p.id, map: p.map_id }, { entity_id: this._robot });
      };
      act("edit").onclick = () => this._presetOpen({ ...p, preset_id: p.id }, `Edit preset ${p.name}`);
      act("dup").onclick = () => this._presetOpen({ ...p, preset_id: null,
        name: uniqueCopyName(p.name, presets.filter((x) => x.map_id === p.map_id).map((x) => x.name)) }, `Duplicate ${p.name}`);
      // A new schedule on the Schedules tab, set to run this preset.
      act("sched").onclick = () => { this._tab = "schedules"; this._editing = { preset_id: p.id, map_id: p.map_id }; this._preEdit = null; this._renderRight(true); };
      act("del").onclick = async () => {
        const sch = p.schedules || [];
        const also = sch.length ? ` Schedules that run it (${sch.map(when).join(", ")}) will be left pointing at nothing; delete or change them too.` : "";
        if (!confirm(`Delete the preset ${p.name} from the robot?${also}`)) return;
        if (await this._call(DOMAIN, "delete_preset", { preset: p.id, map: p.map_id, confirm: true }, { entity_id: this._robot })) { this._preKey = null; this._renderRight(true); }
      };
    });
  }

  // Opens the editor on a working copy: rooms in cleaning order with their levels. A level the
  // robot has not set on a room (no water tank, say) cannot be saved as unset, so it is filled in
  // from the nearest room that has one, else the robot's current level, else the usual default,
  // and marked (e.unset) until the user picks it, so nothing is invented unseen.
  _presetOpen(p, title) {
    const range = { suction: [1, 5], water: [0, 3], passes: [1, 3] }, dflt = { suction: 2, water: 2, passes: 1 };
    const ok = (k, v) => { const n = Number(v); return v != null && v !== "" && Number.isInteger(n) && n >= range[k][0] && n <= range[k][1] ? n : null; };
    const vac = this._st(this._robot), va = (vac && vac.attributes) || {};
    const robot = { suction: FAN.findIndex((f) => f.toLowerCase() === String(va.fan_speed || "").toLowerCase()) + 1 || null,
      water: WATER.indexOf(String(va.water_level || "").toLowerCase()) >= 0 ? WATER.indexOf(String(va.water_level).toLowerCase()) : null, passes: ok("passes", va.clean_passes) };
    const src = (p.rooms || []).map((x) => ({ id: Number(x.id), suction: ok("suction", x.suction), water: ok("water", x.water), passes: ok("passes", x.passes) }));
    const unset = {};
    const rooms = src.map((x, i) => {
      const out = { ...x };
      for (const k of ["suction", "water", "passes"]) {
        if (out[k] != null) continue;
        // The nearest room before it with that level set, else the nearest after it.
        const near = [...src.slice(0, i).reverse(), ...src.slice(i + 1)].find((y) => y[k] != null);
        const [v, from] = near ? [near[k], "the room next to it in this preset"] : robot[k] != null ? [robot[k], "the robot's current setting"] : [dflt[k], "the usual default"];
        out[k] = v; (unset[x.id] ||= {})[k] = from;
      }
      return out;
    });
    const last = rooms[rooms.length - 1];
    this._preEdit = { title, preset_id: p.preset_id ?? null, map_id: p.map_id, name: p.name || "", clean_order: p.clean_order !== false, rooms, unset,
      names: Object.fromEntries((p.rooms || []).map((x) => [Number(x.id), x.name])),
      last: last ? { suction: last.suction, water: last.water, passes: last.passes } : { ...dflt } };
    this._renderRight(true);
  }

  // Each room of a loaded map with what the editor needs: its outline in mm when the integration
  // sends one, its size in m2, and where its badge goes on the picture. Rooms are normally cells in
  // the grid with no outline: their size and centre come from the room geometry (bbox, centre,
  // cells in picture px), from the reply or, for the current map, from the camera; taps and tints
  // use the room-id grid (_presetMask).
  _presetRooms(res) {
    const g = res.geometry, cam = this._st(this._related(this._robot).camera);
    const extra = res.room_geometry || (cam && cam.attributes.map_id === res.map_id ? cam.attributes.room_geometry : null) || [];
    const cell = g ? (g.resolution_mm / 1000) ** 2 : (cam && cam.attributes.map_geometry ? (cam.attributes.map_geometry.resolution_mm / 1000) ** 2 : 0);
    // Without the map's own room list (its read failed), the camera's rooms for the current map.
    const list = res.rooms || extra.map((x) => ({ id: x.id, name: x.name }));
    return list.filter((rm) => rm && rm.id != null).map((rm) => {
      const id = Number(rm.id), x = extra.find((q) => q && Number(q.id) === id) || {};
      const poly = Array.isArray(rm.vertexs) && rm.vertexs.length >= 3 ? rm.vertexs : null;
      return { id, name: rm.name || x.name || `Room ${id}`, poly,
        m2: poly ? polyArea(poly) / 1e6 : (Number(x.cells) || 0) * cell,
        // Where the picture has the room's name (its geometry's centre), else a point inside its outline.
        centre: x.centre || (poly && g ? mmToPx(...polyLabel(poly), g) : null) };
    });
  }

  // The room-id grid from the integration (1 px per map cell, turned like the picture; red =
  // room id, 0 wall, 255 floor, 127 unknown) as { w, h, scale, idx }: idx holds the editor's
  // room index + 1 per cell, 0 for anything that is not one of its rooms. null without a grid
  // (an older integration): rooms are then picked from the list only.
  _presetMask(maskImg, rooms, geom, picW) {
    if (!maskImg || !maskImg.naturalWidth) return null;
    const w = maskImg.naturalWidth, h = maskImg.naturalHeight, c = document.createElement("canvas");
    c.width = w; c.height = h;
    const ctx = c.getContext("2d"); ctx.drawImage(maskImg, 0, 0);
    let px; try { px = ctx.getImageData(0, 0, w, h).data; } catch (e) { return null; }
    const at = new Map(rooms.map((rm, i) => [rm.id, i + 1])), idx = new Int16Array(w * h);
    for (let i = 0; i < w * h; i++) { const v = px[i * 4]; if (v !== 0 && v !== 127 && v !== 255) idx[i] = at.get(v) || 0; }
    return { w, h, idx, scale: (geom && geom.scale_px_per_cell) || picW / w };
  }

  _renderPresetEditor(pane, r) {
    const e = this._preEdit, robot = this._robot, data = (this._pre && this._pre.data) || { maps: [], presets: [] };
    const map = data.maps.find((m) => m.id === e.map_id);
    const fans = fanLevels([...data.presets, { rooms: e.rooms }]);
    pane.innerHTML = `<ha-card><div class="card form">
      <h3><span>${esc(e.title)}</span><span class="src">${map ? esc(map.name || `Map ${map.id}`) : `Map ${esc(e.map_id)}`}${map && !map.current ? " (not the current map)" : ""}</span></h3>
      <div><label for="pname">Name</label><input class="rename pname" id="pname" maxlength="40" autocomplete="off" value="${esc(e.name)}"></div>
      <div><label>Rooms: tap them on the map or below, in the order to clean them</label>
        <div class="estage pstage"><canvas class="pcanvas" aria-label="Map: tap a room to add it or take it out"></canvas></div>
        <div class="s pstatus" style="margin-top:6px">Loading the map...</div>
        <div class="chips prooms" style="margin-top:8px"></div></div>
      <div class="pgrp"><div style="flex:1"><div>Clean in this order</div><div class="s" style="font-size:.82em;color:var(--secondary-text-color)">Off: the robot picks its own way round.</div></div>
        ${toggle(e.clean_order, "Clean in this order", 'data-order')}</div>
      <div class="ppicked"></div>
      <div class="note pest" style="margin:0"></div>
      <div class="err" hidden></div>
      <div class="actions"><button class="btn cancel">Cancel</button><button class="btn primary save"><ha-icon icon="mdi:content-save"></ha-icon>${e.preset_id != null ? "Save" : "Add to robot"}</button></div>
    </div></ha-card>`;
    const q = (sel) => pane.querySelector(sel), list = q(".ppicked"), canvas = q(".pcanvas");
    // The loaded map: picture, geometry, rooms (sizes, badge spots, outlines if any), room-id grid.
    const view = { img: null, geom: null, rooms: [], mask: null, loaded: false, runs: null };
    const byId = (id) => view.rooms.find((rm) => rm.id === id);
    const nameOf = (id) => (byId(id) || {}).name || e.names[id] || `Room ${id}`;
    const gone = (id) => view.loaded && !byId(id);
    const picked = (id) => e.rooms.some((x) => x.id === id);

    const opts = (k, v) => (k === "suction" ? fans.map((n) => `<option value="${n}" ${v === n ? "selected" : ""}>${FAN[n - 1]}</option>`)
      : k === "water" ? WATER.map((w, n) => `<option value="${n}" ${v === n ? "selected" : ""}>Water ${w}</option>`)
      : [1, 2, 3].map((n) => `<option value="${n}" ${v === n ? "selected" : ""}>${n} pass${n === 1 ? "" : "es"}</option>`)).join("");
    const what = { suction: "Suction", water: "Water", passes: "Passes" };
    // The "all rooms" choices show the level every room shares, else "Mixed".
    const common = (k) => { const vs = new Set(e.rooms.map((x) => x[k])); return vs.size === 1 ? [...vs][0] : null; };
    const allSel = (k) => `<select data-all="${k}" aria-label="${what[k]} for every room">${common(k) == null ? `<option value="" selected disabled>Mixed</option>` : ""}${opts(k, common(k))}</select>`;

    const drawChips = () => {
      const ids = [...view.rooms.map((rm) => rm.id), ...e.rooms.map((x) => x.id).filter((id) => !byId(id))];
      q(".prooms").innerHTML = ids.map((id) => `<button class="chip ${picked(id) ? "on" : ""}" data-room="${id}" aria-pressed="${picked(id)}">${esc(nameOf(id))}${gone(id) ? " (gone)" : ""}</button>`).join("");
    };
    const drawList = () => {
      // Keep keyboard focus on the same control of the same room across the redraw.
      const a = this.shadowRoot.activeElement, row = a && list.contains(a) ? a.closest(".pk") : null;
      const attr = a && ["k", "all", "mv"].find((k) => a.dataset[k] != null);
      const focus = row && attr ? `.pk[data-id="${row.dataset.id}"] [data-${attr}="${a.dataset[attr]}"]` : null;
      list.innerHTML = e.rooms.length ? `<div class="pk all" data-id="all"><span></span><span></span><span class="nm">All rooms</span><div class="lv">${allSel("suction")}${allSel("water")}${allSel("passes")}</div><span></span></div>` +
        e.rooms.map((x, i) => {
          const n = nameOf(x.id);
          return `<div class="pk" data-id="${x.id}"><span class="grip" title="Drag to change the order"><ha-icon icon="mdi:drag"></ha-icon></span>
            <span class="num">${i + 1}</span><span class="nm" title="${esc(n)}">${esc(n)}${gone(x.id) ? " <small>(gone)</small>" : ""}</span>
            <div class="lv">${["suction", "water", "passes"].map((k) => { const was = (e.unset[x.id] || {})[k];
              return `<select data-k="${k}" class="${was ? "unset" : ""}" aria-label="${what[k]} for ${esc(n)}${was ? " (was unset)" : ""}" ${was ? `title="Not set on the robot: filled in from ${esc(was)}. Check it before saving."` : ""}>${opts(k, x[k])}</select>`; }).join("")}</div>
            <span class="ord"><button class="icon-btn" data-mv="-1" title="Move up" aria-label="Move ${esc(n)} up" ${i ? "" : "disabled"}><ha-icon icon="mdi:chevron-up"></ha-icon></button>
              <button class="icon-btn" data-mv="1" title="Move down" aria-label="Move ${esc(n)} down" ${i < e.rooms.length - 1 ? "" : "disabled"}><ha-icon icon="mdi:chevron-down"></ha-icon></button>
              <button class="icon-btn" data-rm title="Take out" aria-label="Take ${esc(n)} out"><ha-icon icon="mdi:close"></ha-icon></button></span></div>`;
        }).join("") + (e.rooms.some((x) => Object.keys(e.unset[x.id] || {}).length)
          ? `<div class="warn" style="margin-top:6px"><ha-icon icon="mdi:alert-outline"></ha-icon>Levels outlined in orange were not set on the robot; they have been filled in for you. Check them before saving.</div>` : "")
        : `<div class="s" style="padding:4px 0">No rooms picked yet.</div>`;
      if (focus) {
        // A row moved to the top or bottom: its other move button takes the focus.
        let el = list.querySelector(focus);
        if (el && el.disabled && el.dataset.mv) el = el.parentElement.querySelector(`[data-mv="${-Number(el.dataset.mv)}"]`);
        if (el && !el.disabled) el.focus();
      }
    };
    const drawMap = () => {
      if (!view.img) return;
      const ctx = canvas.getContext("2d"), g = view.geom, w = canvas.width, h = canvas.height;
      const cs = getComputedStyle(this), primary = cs.getPropertyValue("--primary-color").trim() || "#03a9f4";
      ctx.clearRect(0, 0, w, h); ctx.drawImage(view.img, 0, 0);
      // Rooms without an outline: tinted cell by cell from the room-id grid, scaled up unsmoothed.
      const mk = view.mask;
      if (mk && e.rooms.some((x) => { const rm = byId(x.id); return rm && !rm.poly; })) {
        const on = new Set(e.rooms.map((x) => view.rooms.findIndex((rm) => rm.id === x.id && !rm.poly) + 1).filter((n) => n > 0));
        const layer = document.createElement("canvas"); layer.width = mk.w; layer.height = mk.h;
        const lc = layer.getContext("2d");
        lc.fillStyle = primary; lc.fillRect(0, 0, 1, 1);
        const [pr, pg, pb] = lc.getImageData(0, 0, 1, 1).data;    // the theme colour as rgb
        const tint = lc.createImageData(mk.w, mk.h), d = tint.data;
        for (let i = 0; i < mk.idx.length; i++) if (on.has(mk.idx[i])) { d[i * 4] = pr; d[i * 4 + 1] = pg; d[i * 4 + 2] = pb; d[i * 4 + 3] = 110; }
        lc.putImageData(tint, 0, 0);
        ctx.imageSmoothingEnabled = false; ctx.drawImage(layer, 0, 0, mk.w * mk.scale, mk.h * mk.scale); ctx.imageSmoothingEnabled = true;
      }
      for (const rm of view.rooms) {
        if (!rm.poly) continue;
        ctx.beginPath();
        rm.poly.forEach((p, i) => { const [x, y] = mmToPx(p[0], p[1], g); i ? ctx.lineTo(x, y) : ctx.moveTo(x, y); });
        ctx.closePath();
        if (picked(rm.id)) { ctx.globalAlpha = .4; ctx.fillStyle = primary; ctx.fill(); ctx.globalAlpha = 1; ctx.strokeStyle = primary; ctx.lineWidth = 3; ctx.stroke(); }
        else { ctx.strokeStyle = "rgba(255,255,255,.4)"; ctx.lineWidth = 1; ctx.setLineDash([4, 4]); ctx.stroke(); ctx.setLineDash([]); }
      }
      // Numbered badges in cleaning order, about 12 screen px across whatever the canvas scale,
      // just above the room's name on the picture.
      const k = canvas.width / (canvas.getBoundingClientRect().width || canvas.width), rad = 12 * k;
      ctx.font = `600 ${Math.round(13 * k)}px system-ui, sans-serif`; ctx.textAlign = "center"; ctx.textBaseline = "middle";
      e.rooms.forEach((x, i) => {
        const rm = byId(x.id); if (!rm || !rm.centre) return;
        const cx = rm.centre[0], cy = Math.max(rad + 2, rm.centre[1] - 12 - rad);
        ctx.beginPath(); ctx.arc(cx, cy, rad, 0, 2 * Math.PI); ctx.fillStyle = primary; ctx.fill();
        ctx.lineWidth = 2 * k; ctx.strokeStyle = "#fff"; ctx.stroke();
        ctx.fillStyle = "#fff"; ctx.fillText(String(i + 1), cx, cy + k);
      });
      ctx.textAlign = "start"; ctx.textBaseline = "alphabetic";
    };
    const drawEst = () => {
      const box = q(".pest");
      if (!e.rooms.length || !view.loaded) { box.innerHTML = ""; return; }
      const est = presetEstimate(e.rooms, Object.fromEntries(view.rooms.map((rm) => [rm.id, rm.m2])), view.runs, e.map_id);
      if (!est.m2) { box.innerHTML = "Estimate: the size of these rooms is not known."; return; }
      const m2 = est.m2 < 10 ? est.m2.toFixed(1) : String(Math.round(est.m2));
      const mins = est.minutes == null ? "" : est.minutes >= 60 ? `${Math.floor(est.minutes / 60)} h ${est.minutes % 60} min` : `${est.minutes} min`;
      box.innerHTML = `Estimate: about ${esc(m2)} m&sup2;${e.rooms.some((x) => x.passes > 1) ? " counting every pass" : ""}`
        + (mins ? `, around ${esc(mins)} at this robot's usual pace (from ${est.runs} past clean${est.runs === 1 ? "" : "s"})` : "") + "."
        + (est.unknown ? ` ${est.unknown} room${est.unknown === 1 ? " has" : "s have"} no known size and ${est.unknown === 1 ? "is" : "are"} not counted.` : "");
    };
    const redraw = () => { drawChips(); drawList(); drawMap(); drawEst(); };
    const flip = (id) => {
      const i = e.rooms.findIndex((x) => x.id === id);
      if (i >= 0) { e.rooms.splice(i, 1); delete e.unset[id]; }
      else e.rooms.push({ id, ...e.last });      // new rooms take the last levels used
      redraw();
    };

    q(".pname").oninput = () => { e.name = q(".pname").value; };
    q("[data-order]").onclick = () => {
      e.clean_order = !e.clean_order;
      const b = q("[data-order]"); b.classList.toggle("on", e.clean_order); b.setAttribute("aria-pressed", String(e.clean_order));
    };
    q(".prooms").onclick = (ev) => { const b = ev.target.closest("[data-room]"); if (b) flip(Number(b.dataset.room)); };
    canvas.onclick = (ev) => {
      if (!view.img) return;
      const b = canvas.getBoundingClientRect(), x = ((ev.clientX - b.left) / b.width) * canvas.width, y = ((ev.clientY - b.top) / b.height) * canvas.height;
      const [mx, my] = pxToMm(x, y, view.geom);
      // The smallest outline under the tap wins (a room drawn inside another stays reachable).
      let best = null, area = Infinity;
      for (const rm of view.rooms) if (rm.poly && inPoly(mx, my, rm.poly)) { const a = polyArea(rm.poly); if (a < area) { best = rm; area = a; } }
      // Else the room whose cell is under the tap (room names drawn on the picture included).
      const mk = view.mask, gx = mk ? Math.floor(x / mk.scale) : -1, gy = mk ? Math.floor(y / mk.scale) : -1;
      if (!best && mk && gx >= 0 && gy >= 0 && gx < mk.w && gy < mk.h) { const i = mk.idx[gy * mk.w + gx]; if (i) best = view.rooms[i - 1]; }
      if (best) flip(best.id);
    };
    list.onchange = (ev) => {
      const s = ev.target;
      // A level picked here is the user's own: its "was unset" mark goes.
      if (s.dataset.all) { const k = s.dataset.all, v = Number(s.value); e.rooms.forEach((x) => { x[k] = v; if (e.unset[x.id]) delete e.unset[x.id][k]; }); e.last[k] = v; }
      else if (s.dataset.k) {
        const x = e.rooms.find((y) => String(y.id) === s.closest(".pk").dataset.id); if (!x) return;
        x[s.dataset.k] = Number(s.value); e.last = { suction: x.suction, water: x.water, passes: x.passes };
        if (e.unset[x.id]) delete e.unset[x.id][s.dataset.k];
      }
      drawList(); drawEst();
    };
    list.onclick = (ev) => {
      const b = ev.target.closest("[data-mv], [data-rm]"); if (!b) return;
      const i = e.rooms.findIndex((x) => String(x.id) === b.closest(".pk").dataset.id);
      if (b.dataset.mv) { e.rooms = moveItem(e.rooms, i, i + Number(b.dataset.mv)); drawList(); drawMap(); }
      else flip(e.rooms[i].id);
    };
    // Dragging a row by its grip: the row moves through the list as the pointer passes the middle
    // of the next one, and the numbers and the map's badges follow. The list holds the pointer,
    // so moving the row itself does not drop it.
    let drag = null;
    list.onpointerdown = (ev) => {
      const g = ev.target.closest(".grip"); if (!g) return;
      ev.preventDefault();
      drag = g.closest(".pk"); drag.classList.add("dragging");
      try { list.setPointerCapture(ev.pointerId); } catch (x) { /* the pointer is already gone */ }
    };
    list.onpointermove = (ev) => {
      if (!drag) return;
      const rows = [...list.querySelectorAll(".pk:not(.all)")].filter((x) => x !== drag);
      // Rows stay above the "was unset" note, when there is one.
      const before = rows.find((x) => { const b = x.getBoundingClientRect(); return ev.clientY < b.top + b.height / 2; }) || list.querySelector(":scope > .warn");
      if (before === drag.nextElementSibling) return;
      list.insertBefore(drag, before);
      const ids = [...list.querySelectorAll(".pk:not(.all)")].map((x) => x.dataset.id);
      e.rooms = ids.map((id) => e.rooms.find((x) => String(x.id) === id));
      list.querySelectorAll(".pk:not(.all) .num").forEach((n, i) => { n.textContent = String(i + 1); });
      drawMap();
    };
    list.onpointerup = list.onpointercancel = list.onlostpointercapture = () => { if (!drag) return; drag = null; drawList(); };

    q(".cancel").onclick = () => { this._preEdit = null; this._renderRight(true); };
    q(".save").onclick = async () => {
      const err = q(".err"), save = q(".save"), name = q(".pname").value.trim();
      const fail = (m) => { err.textContent = m; err.hidden = false; };
      err.hidden = true;
      if (!name) return fail("Give the preset a name.");
      if (name.length > 40) return fail("A preset name can be up to 40 characters.");
      if (data.presets.some((p) => p.map_id === e.map_id && p.id !== e.preset_id && foldName(p.name) === foldName(name))) return fail(`This map already has a preset called ${name}.`);
      if (!e.rooms.length) return fail("Pick at least one room.");
      const lost = e.rooms.filter((x) => gone(x.id));
      if (lost.length) return fail(`Take out the rooms no longer on the map: ${lost.map((x) => nameOf(x.id)).join(", ")}.`);
      const msg = { type: `${DOMAIN}/preset/save`, entity_id: robot, map_id: e.map_id, name, clean_order: e.clean_order,
        rooms: e.rooms.map((x) => ({ id: x.id, suction: x.suction, water: x.water, passes: x.passes })) };
      if (e.preset_id != null) msg.preset_id = e.preset_id;
      save.disabled = true; save.classList.add("busy");
      try { await this._hass.callWS(msg); }
      catch (x) {
        if (save.isConnected) { save.disabled = false; save.classList.remove("busy"); fail((x && x.message) || "The robot did not take the preset."); }
        return;
      }
      if (this._robot !== robot || this._preEdit !== e) return;
      this._preEdit = null; this._preKey = null; this._renderRight(true);
    };

    redraw();
    // The map and the past cleans arrive on their own; a reply after the editor closed is dropped.
    const live = () => this._preEdit === e && this._robot === robot && canvas.isConnected;
    this._presetMap(e.map_id).then(({ res, img, mask }) => {
      if (!live()) return;
      view.rooms = this._presetRooms(res); view.loaded = true;
      if (img) {
        view.img = img; view.geom = res.geometry;
        canvas.width = img.naturalWidth; canvas.height = img.naturalHeight;
        view.mask = this._presetMask(mask, view.rooms, res.geometry, img.naturalWidth);
        q(".pstatus").textContent = view.mask || view.rooms.every((rm) => rm.poly) ? ""
          : "Pick the rooms below: this version of the integration does not say where each room is on the picture.";
      } else { q(".pstage").hidden = true; q(".pstatus").textContent = "Could not draw this map; pick the rooms below."; }
      redraw();
    }, (x) => {
      if (!live()) return;
      q(".pstage").hidden = true; q(".pstatus").textContent = `Could not read the map (${(x && x.message) || x}); pick the rooms below.`;
      // The current map's rooms are still known from the camera: offer them as chips.
      const cam = this._st(this._related(robot).camera);
      if (cam && cam.attributes.map_id === e.map_id && (cam.attributes.room_geometry || []).length) {
        view.rooms = this._presetRooms({ map_id: e.map_id, rooms: null }); view.loaded = true; redraw();
      }
    });
    this._presetRuns().then((runs) => { if (live()) { view.runs = runs; drawEst(); } });
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
    <ha-card><div class="card"><h3><span>Recent runs</span><span class="keepbox"></span></h3><div class="keepnote"></div>
      <div class="runs"><div class="empty">Loading</div></div></div></ha-card>`;
    // Refetched when the robot finishes a clean (its total moves), and each time the tab opens.
    const robot = this._robot, key = `${robot}|${tot(r.totals.cleans)}`;
    if (!this._records || this._recordsKey !== key) {
      const tok = this._recTok = {};
      let recs = null, hist = null;
      // The robot's records feed the charts; the kept clean maps (and the robot's runs not kept)
      // feed the list. An integration without clean map history just lists the records.
      const [recResp, histResp] = await Promise.allSettled([
        this._hass.connection.sendMessagePromise({ type: "call_service", domain: DOMAIN, service: "get_clean_records",
          service_data: { entity_id: robot, limit: 100 }, return_response: true }),
        this._hass.callWS({ type: `${DOMAIN}/history/list`, entity_id: robot }),
      ]);
      if (recResp.status === "fulfilled") recs = (recResp.value && recResp.value.response && recResp.value.response.records) || [];
      if (histResp.status === "fulfilled") hist = histResp.value;
      // A reply for a robot no longer shown, or one a newer request has overtaken, is dropped.
      if (this._recTok !== tok || this._robot !== robot) return;
      if (!recs) {
        this._records = null;
        const runs = pane.querySelector(".runs"); if (runs) runs.innerHTML = `<div class="empty">Could not load history</div>`;
        return;
      }
      this._records = recs; this._hist = hist; this._recordsFor = robot; this._recordsKey = key;
    }
    const recs = this._records;
    const runs = pane.querySelector(".runs");
    if (!runs) return;     // the tab changed while the records were loading
    this._renderRuns(pane, r, recs);
    this._chart(pane.querySelector("canvas.days"), this._perDay(recs, 30), (i) => (i % 7 === 0 ? `${29 - i}d` : ""));
    this._chart(pane.querySelector("canvas.weeks"), this._perWeek(recs, 8), (i) => (i === 7 ? "this wk" : `-${7 - i}`));
  }

  _renderRuns(pane, r, recs) {
    const runs = pane.querySelector(".runs"), hist = this._hist;
    const list = hist ? hist.runs : recs;
    const keep = hist ? hist.retention : null;
    // How long maps are kept, set here or as the Clean Map History entity (automations, Settings tab).
    const box = pane.querySelector(".keepbox"), note = pane.querySelector(".keepnote");
    if (hist && r.history) {
      box.innerHTML = `<label class="keep">Keep maps <select>${hist.retention_options.map((o) => `<option ${o === keep ? "selected" : ""}>${esc(o)}</option>`).join("")}</select></label>`;
      const sel = box.querySelector("select");
      sel.onchange = async () => {
        const kept = hist.usage.runs;
        if (sel.value === "Off" && kept && !confirm(`Turn clean map history off? The ${kept} kept map${kept === 1 ? "" : "s"} will be deleted.`)) { sel.value = keep; return; }
        if (await this._call("select", "select_option", { option: sel.value }, { entity_id: r.history })) { this._records = null; this._paneHistory(pane); }
        else sel.value = keep;
      };
    }
    if (note) note.textContent = !hist ? "" : keep === "Off" ? "Clean maps are not kept; a run's map can still be read from the robot while it has the run."
      : `${hist.usage.runs} map${hist.usage.runs === 1 ? "" : "s"} kept (${hist.usage.bytes >= 1048576 ? (hist.usage.bytes / 1048576).toFixed(1) + " MB" : Math.max(1, Math.round(hist.usage.bytes / 1024)) + " KB"}), at most ${hist.limit}.`;
    runs.innerHTML = list.length ? list.slice(0, 40).map((x) => {
      const d = x.started ? new Date(x.started * 1000) : null;
      const when = d ? d.toLocaleDateString(undefined, { weekday: "short", day: "numeric", month: "short" }) + " " + d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" }) : "";
      const meta = [x.area != null ? `${x.area} m²` : null, x.minutes != null ? `${x.minutes} min` : null, START[x.start_type] || null, x.rule_name || null, x.map_name || null, x.emptied_bin ? "bin emptied" : null].filter(Boolean).join(" · ");
      const tag = !hist ? "" : x.kept ? "" : `<span class="src">on robot</span>`;
      const mapBtn = hist && x.started ? `<button class="btn mapbtn" data-ts="${x.started}" aria-expanded="false"><ha-icon icon="mdi:map-search-outline"></ha-icon>Map</button>` : "";
      return `<div class="row"><ha-icon icon="${x.error ? "mdi:alert-circle" : "mdi:robot-vacuum"}" style="color:${x.error ? "var(--error-color,#db4437)" : "var(--primary-color)"}"></ha-icon><div class="main"><div class="t">${esc(when)} ${tag}</div><div class="s">${esc(meta)}${x.error ? ` · error ${esc(x.error)}` : ""}</div></div>${mapBtn}</div>
        <div class="runmap" data-for="${x.started}" hidden></div>`;
    }).join("") : `<div class="empty">No runs recorded yet.</div>`;
    runs.querySelectorAll(".mapbtn").forEach((b) => b.onclick = () => this._toggleRunMap(runs, list, Number(b.dataset.ts), b));
  }

  async _toggleRunMap(runs, list, ts, btn) {
    const box = runs.querySelector(`.runmap[data-for="${ts}"]`);
    if (!box) return;
    const open = box.hidden;
    box.hidden = !open; btn.setAttribute("aria-expanded", String(open));
    if (!open) return;
    const robot = this._robot, run = list.find((x) => x.started === ts) || {};
    this._runImg = this._runImgFor === robot ? (this._runImg || {}) : {};
    this._runImgFor = robot;
    // Kept per way round: turning the map redraws a run already opened.
    const cam = this._st(this._related(robot).camera), maps = (cam && cam.attributes.maps) || [];
    const turn = (maps.find((m) => m.id === run.map_id) || {}).rotation || 0, key = `${ts}-${turn}`;
    if (!this._runImg[key]) {
      box.innerHTML = `<div class="empty">Drawing the map</div>`;
      try {
        const res = await this._hass.callWS({ type: `${DOMAIN}/history/image`, entity_id: robot, started: ts });
        this._runImg[key] = res.image;
      } catch (e) {
        box.innerHTML = `<div class="err">${esc((e && e.message) || "Could not draw that clean")}</div>`;
        return;
      }
      if (this._robot !== robot) return;
    }
    const d = new Date(ts * 1000), pad = (n) => String(n).padStart(2, "0");
    const name = `${objectId(robot)}-clean-${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}.png`;
    box.innerHTML = `<img class="runimg" alt="Map of this clean" src="${this._runImg[key]}">
      <div class="acts"><a class="btn" download="${esc(name)}" href="${this._runImg[key]}"><ha-icon icon="mdi:download"></ha-icon>Download</a>
      ${run.kept ? `<button class="btn danger forget"><ha-icon icon="mdi:delete-outline"></ha-icon>Forget</button>` : ""}</div>`;
    const f = box.querySelector(".forget");
    if (f) f.onclick = async () => {
      if (!confirm("Forget this clean's map? The run stays in the robot's own history while it has it.")) return;
      try { await this._hass.callWS({ type: `${DOMAIN}/history/delete`, entity_id: robot, started: ts }); }
      catch (e) { this.dispatchEvent(new CustomEvent("hass-notification", { detail: { message: (e && e.message) || "Could not forget that map" }, bubbles: true, composed: true })); return; }
      delete this._runImg[key]; this._records = null;
      const pane = runs.closest(".pane"); if (pane) this._paneHistory(pane);
    };
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
    // Carpets and room renaming are read-only for now: carpet writes do not persist
    // standalone, and setAreaInfo "room" can disturb room geometry; both pending safe testing.
    const tools = [["select", "mdi:cursor-move", "Select"], ["forbid", "mdi:cancel", "No-go"],
      ["virtual_wall", "mdi:wall", "Wall"], ["furniture", "mdi:sofa", "Furniture"]];
    pane.innerHTML = `<ha-card><div class="card">
      <div class="emaps"><select class="emap" aria-label="Map to edit"></select>
        <button class="icon-btn eturn" data-dir="270" title="Turn the map anticlockwise"><ha-icon icon="mdi:rotate-left"></ha-icon></button>
        <button class="icon-btn eturn" data-dir="90" title="Turn the map clockwise"><ha-icon icon="mdi:rotate-right"></ha-icon></button>
        <button class="btn euse" style="display:none" title="Make this the map the robot uses"><ha-icon icon="mdi:map-check-outline"></ha-icon>Use this map</button></div>
      <div class="etools">${tools.map(([k, i, l]) => `<button class="btn etool" data-tool="${k}"><ha-icon icon="${i}"></ha-icon>${l}</button>`).join("")}
        <select class="efurn" title="Furniture type"></select>
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
      <div class="s enote"></div>
    </div></ha-card>`;
    const q = (s) => pane.querySelector(s);
    this._editEl = { canvas: q(".ecanvas"), rooms: q(".erooms"), status: q(".estatus"), furn: q(".efurn") };
    this._edit = { tool: "select", sel: null, areas: null, furniture: [], rooms: [], undo: [], img: null, geom: null, mapId: null,
      want: (this._editWant || {})[this._robot] || null, robot: this._robot };
    this._editEl.map = q(".emap"); this._editEl.use = q(".euse"); this._editEl.note = q(".enote");
    q(".emap").onchange = (e) => {
      if (this._edit.undo.length) {     // never drop unsaved edits by switching maps
        e.target.value = String(this._edit.mapId);
        this._editEl.status.textContent = "Save or discard your changes before editing another map.";
        return;
      }
      this._edit.want = Number(e.target.value);
      this._editWant = { ...(this._editWant || {}), [this._robot]: this._edit.want };
      this._editLoad();
    };
    pane.querySelectorAll(".eturn").forEach((b) => b.onclick = async () => {
      if (this._edit.mapId == null || !this._edit.geom) return;
      const to = ((this._edit.geom.rotation || 0) + Number(b.dataset.dir)) % 360;
      const turns = pane.querySelectorAll(".eturn"), picker = this._editEl.map;
      turns.forEach((x) => { x.disabled = true; }); picker.disabled = true;
      this._editEl.status.textContent = "Turning the map...";
      // Edits are kept in mm, so unsaved ones survive the turn: only the picture is redrawn.
      try {
        if (await this._call(DOMAIN, "set_map_rotation", { map: String(this._edit.mapId), rotation: to }, { entity_id: this._robot }))
          await this._editLoad(true);
        else this._editEl.status.textContent = "";
      } finally { turns.forEach((x) => { x.disabled = false; }); picker.disabled = false; }
    });
    q(".euse").onclick = async () => {
      const b = q(".euse"), id = this._edit.mapId, st = this._editEl.status;
      b.disabled = true;
      if (!(await this._call(DOMAIN, "set_map", { map: String(id) }, { entity_id: this._robot }))) { b.disabled = false; return; }
      // The robot relocalises on the map and the map is redrawn: say so until it shows as current.
      st.innerHTML = `<div class="pending" style="display:flex;gap:10px;align-items:center"><span>Switching the robot to this map...</span><div class="ibar"></div></div>`;
      const since = Date.now(), timer = setInterval(() => {
        const cam = this._st(this._related(this._robot).camera);
        const now = cam && cam.attributes.map_id === id;
        if (now || Date.now() - since > 90000 || !st.isConnected) {
          clearInterval(timer);
          if (!st.isConnected) return;
          st.textContent = now ? "The robot now uses this map." : "The robot has not confirmed the switch yet; check the map selector.";
          if (now) { b.style.display = "none"; this._editEl.note.textContent = ""; }
          b.disabled = false;
        }
      }, 1000);
    };

    this._editFurnTypes(null);
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

  // The type list and names from the edit_get reply ({"<code>": "<label>"}), else the built-in list.
  _editFurnTypes(types) {
    const list = types && typeof types === "object" && Object.keys(types).length
      ? Object.entries(types).map(([c, n]) => [Number(c), String(n)]).filter(([c]) => Number.isInteger(c)) : FURN_FALLBACK;
    this._furnNames = Object.fromEntries(list);
    const sel = this._editEl && this._editEl.furn; if (!sel) return;
    const was = sel.value;
    sel.innerHTML = list.map(([c, n]) => `<option value="${c}">${esc(n)}</option>`).join("");
    if (list.some(([c]) => String(c) === was)) sel.value = was;
  }

  _editGeom() { return this._edit.geom; }
  // Editing is done in mm; only drawing and pointer positions go through these (mmToPx, pxToMm),
  // so a turned map (geom.rotation) saves exactly what an unturned one would.
  _editMm2Px(x, y) { return mmToPx(x, y, this._edit.geom); }
  _editPx2Mm(px, py) { return pxToMm(px, py, this._edit.geom); }
  _editPoint(e) {
    const c = this._editEl.canvas, b = c.getBoundingClientRect(), clamp = (v, max) => Math.max(0, Math.min(max, v));
    return [clamp((e.clientX - b.left) / b.width * c.width, c.width), clamp((e.clientY - b.top) / b.height * c.height, c.height)];
  }

  // Loads the chosen map (the current one by default) with its own picture and geometry, drawn
  // together by the integration so they always agree. keep: after a turn, keep the edits made so
  // far (they are in mm) and only redraw.
  async _editLoad(keep, after) {
    const r = this._related(this._robot), cam = this._st(r.camera);
    const maps = ((cam && cam.attributes.maps) || []).filter((m) => m.saved !== false);
    const tok = this._editTok = {}, el = this._editEl;    // a newer load (or pane) wins
    const was = { map: this._edit.mapId, robot: this._edit.robot };
    let want = this._edit.want;
    if (want == null || !maps.some((m) => m.id === want)) want = cam ? cam.attributes.map_id : null;
    el.map.innerHTML = maps.map((m) => `<option value="${m.id}" ${m.id === want ? "selected" : ""}>${esc(m.name || `Map ${m.id}`)}${m.current ? " (current)" : ""}</option>`).join("");
    el.map.style.display = maps.length > 1 ? "" : "none";
    el.status.textContent = keep ? "Redrawing the map..." : "Loading map...";
    if (want == null) { el.status.textContent = "No map available yet."; return; }
    let res;
    try { res = await this._hass.callWS({ type: "tapo_rv30/map/edit_get", entity_id: this._robot, map_id: want, picture: true }); }
    catch (err) { if (this._editTok === tok) el.status.textContent = "Could not read the map: " + (err.message || err); return; }
    if (this._editTok !== tok) return;
    if (!res.picture || !res.geometry) { el.status.textContent = "Could not draw the map."; return; }
    const img = new Image();
    img.onerror = () => { if (this._editTok === tok) el.status.textContent = "Could not load the map picture."; };
    img.onload = () => {
      if (this._editTok !== tok) return;
      const c = this._editEl.canvas; c.width = img.naturalWidth; c.height = img.naturalHeight;
      // Edits are only carried over onto the same map of the same robot (a turn); anything else
      // starts from what that map has.
      const same = keep && was.map === res.map_id && was.robot === this._robot && this._edit.areas;
      this._edit.img = img; this._edit.geom = res.geometry; this._edit.mapId = res.map_id; this._edit.robot = this._robot;
      el.use.style.display = res.current ? "none" : "";
      if (!same) {
        this._edit.areas = res.areas || {}; this._edit.furniture = res.furniture || []; this._edit.rooms = res.rooms || [];
        this._edit.sel = null; this._edit.undo = [];
      }
      this._editFurnTypes(res.furniture_types);
      this._editRenderRooms(); this._editDraw();
      const info = maps.find((m) => m.id === res.map_id) || {};
      el.status.textContent = after || "";
      el.note.textContent = [res.current ? "" : "Editing a map the robot is not using right now; saving writes to this map and the robot stays on its own.",
        info.locked ? "This map is locked: cleans do not update it, but no-go zones, walls and furniture can still be edited." : ""].filter(Boolean).join(" ");
    };
    img.src = res.picture;
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
    for (const [i, f] of (this._edit.furniture || []).entries()) {
      // The robot bakes the furniture picture into the map render, which only refreshes on
      // Save. Shade and label the box so the furniture reads as moved straight away; drawn
      // first and see-through, so no-go zones and walls on top of it stay visible.
      poly(f.vertexs); ctx.closePath(); ctx.fillStyle = "rgba(60,90,150,.35)"; ctx.fill();
      ctx.strokeStyle = "rgba(230,238,250,.95)"; ctx.lineWidth = this._editSelMatch("furniture", i) ? 4 : 2; ctx.stroke();
      const cx = f.vertexs.reduce((s, p) => s + p[0], 0) / f.vertexs.length, cy = f.vertexs.reduce((s, p) => s + p[1], 0) / f.vertexs.length;
      const [px, py] = this._editMm2Px(cx, cy); ctx.fillStyle = "#fff"; ctx.strokeStyle = "rgba(0,0,0,.6)"; ctx.lineWidth = 3; ctx.font = "11px system-ui, sans-serif"; ctx.textAlign = "center"; ctx.textBaseline = "middle";
      const name = this._furnNames?.[f.type] || "Furniture"; ctx.strokeText(name, px, py); ctx.fillText(name, px, py); ctx.textAlign = "start"; ctx.textBaseline = "alphabetic";
    }
    for (const t of ["forbid", "carpet_rectangle", "carpet_round"]) for (const [i, a] of (this._edit.areas[t] || []).entries()) {
      poly(a.vertexs); ctx.closePath(); ctx.fillStyle = styles[t][0]; ctx.fill();
      ctx.strokeStyle = styles[t][1]; ctx.lineWidth = this._editSelMatch(t, i) ? 4 : 2; ctx.setLineDash(t === "forbid" ? [] : [6, 4]); ctx.stroke(); ctx.setLineDash([]);
    }
    for (const [i, a] of (this._edit.areas.virtual_wall || []).entries()) {
      poly(a.vertexs); ctx.strokeStyle = "rgba(150,70,210,.95)"; ctx.lineWidth = this._editSelMatch("virtual_wall", i) ? 6 : 4; ctx.stroke();
    }
    const hd = this._editHandle();
    if (hd) { const r = this._editHandleR() / 2; ctx.fillStyle = "#fff"; ctx.strokeStyle = "rgba(40,110,220,.95)"; ctx.lineWidth = 2; ctx.fillRect(hd[0] - r, hd[1] - r, 2 * r, 2 * r); ctx.strokeRect(hd[0] - r, hd[1] - r, 2 * r, 2 * r); }
    if (this._edit.drag) { const d = this._edit.drag; ctx.strokeStyle = "rgba(40,110,220,.95)"; ctx.lineWidth = 2; ctx.setLineDash([5, 4]); if (d.line) { ctx.beginPath(); ctx.moveTo(d.x0, d.y0); ctx.lineTo(d.x1, d.y1); ctx.stroke(); } else { ctx.strokeRect(Math.min(d.x0, d.x1), Math.min(d.y0, d.y1), Math.abs(d.x1 - d.x0), Math.abs(d.y1 - d.y0)); } ctx.setLineDash([]); }
  }

  _editSelMatch(kind, i) { const s = this._edit.sel; return s && s.kind === kind && s.i === i; }
  _editSnapshot() { this._edit.undo.push(JSON.stringify({ areas: this._edit.areas, furniture: this._edit.furniture, rooms: this._edit.rooms })); if (this._edit.undo.length > 30) this._edit.undo.shift(); }

  _editReady() { return !!(this._edit && this._edit.img && this._edit.geom && this._edit.areas); }
  _editDown(e) {
    if (!this._editReady()) return;     // nothing to draw on until the map has loaded
    try { this._editEl.canvas.setPointerCapture(e.pointerId); } catch (err) { /* the pointer is already gone */ }
    const [x, y] = this._editPoint(e); const t = this._edit.tool;
    if (t === "select") {
      // The selected furniture's bottom right handle resizes it about its fixed top left corner.
      const hd = this._editHandle();
      if (hd && Math.hypot(x - hd[0], y - hd[1]) <= this._editHandleR()) { this._edit.resizing = true; return; }
      this._edit.sel = this._editHit(x, y); if (this._edit.sel) this._edit.moveFrom = this._editPx2Mm(x, y); this._editDraw(); return;
    }
    if (t === "furniture") {
      this._editSnapshot(); const [mx, my] = this._editPx2Mm(x, y); const type = Number(this._editEl.furn.value);
      const [w, d] = FURN_SIZE[type] || [700, 500], hw = w / 2, hh = d / 2;
      // A fresh id: the robot keys furniture by id, so a second id 0 would clash with the first.
      const id = Math.max(-1, ...this._edit.furniture.map((f) => Number(f.id)).filter(Number.isFinite)) + 1;
      this._edit.furniture.push({ type, id, angle: 0, vertexs: mmBox(mx - hw, my + hh, mx + hw, my - hh) });
      this._edit.sel = { kind: "furniture", i: this._edit.furniture.length - 1 }; this._editDraw(); return;
    }
    this._edit.drag = { x0: x, y0: y, x1: x, y1: y, line: t === "virtual_wall" };
  }
  _editMove(e) {
    if (!this._editReady()) return;
    const [x, y] = this._editPoint(e);
    if (this._edit.drag) { this._edit.drag.x1 = x; this._edit.drag.y1 = y; this._editDraw(); return; }
    if (this._edit.resizing && (e.buttons & 1)) {
      const it = this._editSelItem(); if (!it) return;
      if (!this._edit.moving) { this._editSnapshot(); this._edit.moving = true; }
      const [mx, my] = this._editPx2Mm(x, y), l = Math.min(...it.vertexs.map((p) => p[0])), t = Math.max(...it.vertexs.map((p) => p[1]));
      it.vertexs = mmBox(l, t, Math.max(mx, l + FURN_MIN), Math.min(my, t - FURN_MIN)); this._editDraw(); return;
    }
    if (this._edit.tool === "select" && this._edit.sel && this._edit.moveFrom && (e.buttons & 1)) {
      const [mx, my] = this._editPx2Mm(x, y); const dx = mx - this._edit.moveFrom[0], dy = my - this._edit.moveFrom[1];
      if (!this._edit.moving) { this._editSnapshot(); this._edit.moving = true; }
      this._edit.moveFrom = [mx, my]; const it = this._editSelItem(); if (it) it.vertexs = it.vertexs.map(([a, b]) => [a + dx, b + dy]); this._editDraw();
    }
  }
  _editUp(e) {
    this._edit.moving = false; this._edit.moveFrom = null; this._edit.resizing = false;
    if (!this._editReady()) { this._edit.drag = null; return; }
    const d = this._edit.drag; if (!d) return; this._edit.drag = null;
    const moved = Math.hypot(d.x1 - d.x0, d.y1 - d.y0); if (moved < 6) { this._editDraw(); return; }
    const [ax, ay] = this._editPx2Mm(d.x0, d.y0), [bx, by] = this._editPx2Mm(d.x1, d.y1); this._editSnapshot();
    // The same corner order whichever way the drag went: zones as mmBox, walls from their left
    // end (the top one when upright).
    if (this._edit.tool === "virtual_wall") { const ends = (ax < bx || (ax === bx && ay >= by)) ? [[ax, ay], [bx, by]] : [[bx, by], [ax, ay]]; (this._edit.areas.virtual_wall ||= []).push({ id: 0, vertexs: ends }); }
    else { const t = this._edit.tool; (this._edit.areas[t] ||= []).push({ id: 0, vertexs: mmBox(ax, ay, bx, by) }); }
    this._editDraw();
  }

  _editCancel() {
    if (!this._edit) return;
    this._edit.moving = false; this._edit.moveFrom = null; this._edit.resizing = false;
    if (this._edit.drag) { this._edit.drag = null; this._editDraw(); }
  }

  _editHit(x, y) {
    const inside = (verts) => inPoly(x, y, verts.map((p) => this._editMm2Px(p[0], p[1])));
    const near = (verts) => { const [x0, y0] = this._editMm2Px(verts[0][0], verts[0][1]), [x1, y1] = this._editMm2Px(verts[1][0], verts[1][1]); const L = Math.hypot(x1 - x0, y1 - y0) || 1; return Math.abs((y1 - y0) * x - (x1 - x0) * y + x1 * y0 - y1 * x0) / L < 8; };
    // The smallest item under the pointer wins, so a zone inside a furniture box stays selectable
    // (a wall counts as no area: it is hit only near its line).
    const area = polyArea;
    let best = null, bestArea = Infinity;
    const take = (kind, i, a) => { if (a < bestArea) { best = { kind, i }; bestArea = a; } };
    for (const [i, f] of (this._edit.furniture || []).entries()) if (inside(f.vertexs)) take("furniture", i, area(f.vertexs));
    for (const [i, a] of (this._edit.areas.forbid || []).entries()) if (inside(a.vertexs)) take("forbid", i, area(a.vertexs));
    for (const [i, a] of (this._edit.areas.virtual_wall || []).entries()) if (near(a.vertexs)) take("virtual_wall", i, 0);
    return best;
  }
  // Where the selected furniture's resize handle is (its bottom right corner, canvas px), or null.
  // Turned items have none: resizing keeps the box square to the map.
  _editHandle() {
    const s = this._edit.sel; if (this._edit.tool !== "select" || !s || s.kind !== "furniture") return null;
    const f = this._edit.furniture[s.i]; if (!f || Number(f.angle) || !f.vertexs || !f.vertexs.length) return null;
    return this._editMm2Px(Math.max(...f.vertexs.map((p) => p[0])), Math.min(...f.vertexs.map((p) => p[1])));
  }
  // The handle's size in canvas px: about 14 screen px however the canvas is scaled.
  _editHandleR() { const c = this._editEl.canvas, w = c.getBoundingClientRect().width; return 14 * (w ? c.width / w : 1); }
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
    try {
      const r = await this._hass.callWS(payload), w = r && r.result && r.result.warning;
      this._editLoad(false, w ? `Saved, but ${w}.` : "Saved.");
    }
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
    grid.querySelectorAll(".bkrestore").forEach((el) => { el.onclick = () => this._backupRestore(list[+el.dataset.i], status, el); el.disabled = !this._isAdmin(); });
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

  // A progress bar for a long map job (copy, restore), fed by the integration's tapo_rv30_map_job
  // events for this robot. Returns { stop() }; it also stops itself when the job ends.
  _jobBar(host, job, first) {
    const box = document.createElement("div");
    box.className = "jobbar";
    box.innerHTML = `<div class="track"><div class="fill"></div></div><div class="lbl"><span class="st"></span><span class="pc"></span></div>`;
    host.appendChild(box);
    const set = (stage, pc, bad) => {
      box.querySelector(".fill").style.width = `${Math.max(3, pc)}%`;
      box.querySelector(".st").textContent = stage;
      box.querySelector(".pc").textContent = `${Math.round(pc)}%`;
      box.classList.toggle("bad", !!bad);
    };
    set(first || "Starting...", 0);
    let unsub = null, stopped = false;
    const stop = () => { stopped = true; if (unsub) { unsub(); unsub = null; } };
    this._hass.connection.subscribeEvents((ev) => {
      const d = ev.data || {};
      if (d.entity_id !== this._robot || d.job !== job) return;
      set(d.error ? `${d.stage}: ${d.error}` : d.stage, d.percent, !!d.error);
      if (d.done) stop();
    }, "tapo_rv30_map_job").then((u) => { if (stopped) u(); else unsub = u; }).catch(() => {});
    return { stop, set, el: box };
  }

  // Restore choices, in the card (no browser dialog, which app webviews may not show): over the
  // map the backup came from, or as a new map with its own name next to it.
  _backupRestore(b, status, btn) {
    const meta = btn && btn.closest(".meta");
    if (!meta || meta.querySelector(".restore-opts")) return;
    const grp = `how-${Math.random().toString(36).slice(2)}`;   // one radio group per card
    const cam = this._st(this._related(this._robot).camera), maps = ((cam && cam.attributes.maps) || []);
    const onRobot = maps.some((m) => String(m.id) === String(b.map_id));
    const full = maps.length >= 3;
    const acts = meta.querySelector(".acts");
    const box = document.createElement("div");
    box.className = "restore-opts";
    box.innerHTML = `
      <label><input type="radio" name="${grp}" value="replace" checked>${onRobot ? `Replace "${esc(b.map_name)}" on the robot` : `Put "${esc(b.map_name)}" back (it is no longer on the robot)`}</label>
      <label class="${full ? "off" : ""}" ${full ? `title="The robot holds at most 3 maps; delete one first"` : ""}><input type="radio" name="${grp}" value="new" ${full ? "disabled" : ""}>As a new map${full ? " (the robot already has 3; delete one first)" : ""}</label>
      <input class="rename" maxlength="32" aria-label="New map name" value="${esc(`${b.map_name} copy`.slice(0, 32))}" style="display:none">
      <div class="acts"><button class="btn primary" data-act="go"><ha-icon icon="mdi:backup-restore"></ha-icon>Restore</button><button class="btn" data-act="cancel">Cancel</button></div>`;
    acts.style.display = "none";
    meta.appendChild(box);
    const name = box.querySelector("input.rename"), how = () => (box.querySelector(`input[name="${grp}"]:checked`) || {}).value;
    box.querySelectorAll(`input[name="${grp}"]`).forEach((r) => r.onchange = () => { name.style.display = how() === "new" ? "" : "none"; if (how() === "new") name.focus(); });
    const close = () => { box.remove(); acts.style.display = ""; };
    box.querySelector("[data-act=cancel]").onclick = close;
    box.querySelector("[data-act=go]").onclick = () => {
      const asNew = how() === "new", newName = name.value.trim();
      if (asNew && !newName) { name.focus(); return; }
      close();
      const data = { map: String(b.map_id), file: b.file, confirm: true };
      if (asNew) data.new_name = newName;
      status.textContent = (asNew ? `Restoring "${b.map_name}" as a new map, "${newName}".` : `Restoring "${b.map_name}".`)
        + " This takes a minute or two; keep the robot docked.";
      const bar = this._jobBar(status, "restore", "Starting the restore");
      this._hass.callService(DOMAIN, "restore_map_backup", data, { entity_id: this._robot }, false, true)
        .then((res) => {
          bar.stop(); bar.el.remove();
          const r = (res && res.response) ? res.response : res;
          if (r && r.applied) status.textContent = `${asNew ? `Restored as "${newName}".` : `Restored "${b.map_name}".`} ${r.next_steps || ""}${r.note ? " " + r.note : ""}`;
          else status.textContent = `Restore ended without confirmation: ${r && r.note ? r.note : "check the robot"}.`;
        })
        .catch((e) => { bar.stop(); bar.el.remove(); status.textContent = "Restore failed: " + (e.message || e); });
    };
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
  // Shows a row as busy until done(map entry) holds in the map list (or 90 s), then redraws it.
  _pendMap(pane, id, label, done) {
    this._mapPending = { ...(this._mapPending || {}), [String(id)]: { label, done, since: Date.now() } };
    this._paneSettings(pane);
    clearInterval(this._mapPendTimer);
    this._mapPendTimer = setInterval(() => {       // also redraw when nothing else changes
      if (!pane.isConnected || !Object.keys(this._mapPending || {}).length) { clearInterval(this._mapPendTimer); return; }
      if (this._tab === "settings" && !this._formBusy()) this._paneSettings(pane);
    }, 1500);
  }

  _paneSettings(pane) {
    const r = this._related(this._robot), strip = (id) => this._label(id);
    const sw = r.switches.map((id) => { const s = this._st(id); return `<div class="row"><div class="main"><div class="t">${esc(strip(id))}</div></div>${toggle(s.state === "on", strip(id), `data-sw="${esc(id)}"`)}</div>`; }).join("");
    const sel = r.selects.map((id) => { const s = this._st(id); return `<div class="row"><div class="main"><div class="t">${esc(strip(id))}</div></div><select data-sel="${esc(id)}">${(s.attributes.options || []).map((o) => `<option ${o === s.state ? "selected" : ""}>${esc(o)}</option>`).join("")}</select></div>`; }).join("");
    const num = r.numbers.map((id) => { const s = this._st(id); return `<div class="row"><div class="main"><div class="t">${esc(strip(id))}</div><div class="s">${esc(s.state)} ${esc(s.attributes.unit_of_measurement || "")}</div></div><input type="range" data-num="${esc(id)}" min="${toNum(s.attributes.min)}" max="${toNum(s.attributes.max, 100)}" step="${toNum(s.attributes.step, 1) || 1}" value="${esc(s.state)}"></div>`; }).join("");
    const tim = r.times.map((id) => { const s = this._st(id); return `<div class="row"><div class="main"><div class="t">${esc(strip(id))}</div></div><input type="time" data-time="${esc(id)}" value="${esc(String(s.state).slice(0, 5))}"></div>`; }).join("");
    // Saved maps, renamed on the robot as in the app. Everything here follows a map by id, so a
    // rename only touches automations that name the map.
    const cam = this._st(r.camera), maps = ((cam && cam.attributes.maps) || []).filter((m) => m.saved !== false);
    const admin = this._isAdmin();
    const lockTxt = (m) => m.locked === undefined ? "" : m.auto_locked ? " &middot; locked by the robot" : m.locked ? " &middot; locked" : " &middot; unlocked";
    // A change the robot has accepted but the map list does not show yet (it is re-read and
    // redrawn, a few seconds): the row says so instead of looking as if nothing happened.
    const allMaps = (cam && cam.attributes.maps) || [], pend = this._mapPending || {};
    for (const [id, p] of Object.entries(pend)) {
      const m = allMaps.find((x) => String(x.id) === id);
      if (p.done(m) || Date.now() - p.since > 90000) delete pend[id];
    }
    const pendHtml = (m) => pend[String(m.id)] ? `<div class="pending"><span>${esc(pend[String(m.id)].label)}</span><div class="ibar"></div></div>` : "";
    const mapRows = maps.map((m) => pend[String(m.id)] ? `<div class="row maprow" data-map="${esc(m.id)}"><div class="main"><div class="t">${esc(m.name || `Map ${m.id}`)}</div></div>${pendHtml(m)}</div>` : `<div class="row maprow" data-map="${esc(m.id)}"><div class="main"><div class="t">${esc(m.name || `Map ${m.id}`)}</div><div class="s">${m.current ? "Current map" : "Saved map"} &middot; turned ${esc(m.rotation || 0)}&deg;${lockTxt(m)} &middot; id ${esc(m.id)}</div></div>
      <div class="mapacts">
      ${m.locked === undefined ? "" : `<button class="icon-btn" data-lock="${esc(m.id)}" data-to="${m.locked ? "0" : "1"}" ${admin ? `title="${m.locked ? "Unlock: let later cleans update this map" : "Lock: keep this map as it is; later cleans no longer update it"}"` : `disabled title="Only an administrator can lock maps"`}><ha-icon icon="${m.locked ? "mdi:lock" : "mdi:lock-open-variant-outline"}"></ha-icon></button>`}
      <button class="icon-btn" data-preview="${esc(m.id)}" data-name="${esc(m.name || `Map ${m.id}`)}" title="Preview this map"><ha-icon icon="mdi:eye-outline"></ha-icon></button>
      <button class="icon-btn" data-turn="${esc(m.id)}" data-to="${((m.rotation || 0) + 270) % 360}" title="Turn anticlockwise"><ha-icon icon="mdi:rotate-left"></ha-icon></button>
      <button class="icon-btn" data-turn="${esc(m.id)}" data-to="${((m.rotation || 0) + 90) % 360}" title="Turn clockwise"><ha-icon icon="mdi:rotate-right"></ha-icon></button>
      <button class="btn" data-rename="${esc(m.id)}" data-name="${esc(m.name || "")}" ${admin ? "" : `disabled title="Only an administrator can rename maps"`}><ha-icon icon="mdi:rename-outline"></ha-icon>Rename</button>
      <button class="btn" data-copy="${esc(m.id)}" data-name="${esc(m.name || "")}" ${!admin ? `disabled title="Only an administrator can copy maps"` : maps.length >= 3 ? `disabled title="The robot holds at most 3 maps; delete one first"` : ""}><ha-icon icon="mdi:content-copy"></ha-icon>Copy</button>
      <button class="icon-btn" data-delete="${esc(m.id)}" data-name="${esc(m.name || "")}" ${!admin ? `disabled title="Only an administrator can delete maps"` : m.current ? `disabled title="This is the current map; switch to another map to delete it"` : maps.length < 2 ? `disabled title="The robot needs at least one map"` : `title="Delete this map"`}><ha-icon icon="mdi:delete-outline"></ha-icon></button></div></div>`).join("");
    pane.innerHTML = `${maps.length ? `<ha-card><div class="card"><h3><span>Maps</span></h3>${mapRows}</div></ha-card>` : ""}
      <ha-card><div class="card"><h3><span>Settings</span></h3>${sw}${sel}${tim}${num}${(sw || sel || num || tim) ? "" : `<div class="empty">No settings entities.</div>`}</div></ha-card>`;
    pane.querySelectorAll("[data-turn]").forEach((b) => b.onclick = async () => {
      // Both turn buttons of the map wait for the robot's new angle (the pane redraws then), so a
      // quick second press turns from the new angle instead of repeating the first.
      const both = pane.querySelectorAll(`[data-turn="${b.dataset.turn}"]`);
      both.forEach((x) => { x.disabled = true; });
      const to = Number(b.dataset.to);
      if (await this._call(DOMAIN, "set_map_rotation", { map: b.dataset.turn, rotation: to }, { entity_id: this._robot }))
        this._pendMap(pane, b.dataset.turn, "Turning the map...", (m) => !m || m.rotation === to);
      else both.forEach((x) => { x.disabled = false; });
    });
    // Drawn on request for any saved map (not just the current one), full size over the page.
    pane.querySelectorAll("[data-preview]").forEach((b) => b.onclick = async () => {
      const box = document.createElement("div");
      box.className = "lightbox";
      box.innerHTML = `<img alt="map preview"><div class="lb-info">Drawing ${esc(b.dataset.name)}...</div>`;
      box.onclick = () => box.remove();
      this.shadowRoot.appendChild(box);
      try {
        const res = await this._hass.callWS({ type: "tapo_rv30/map/edit_get", entity_id: this._robot, map_id: Number(b.dataset.preview), picture: true });
        box.querySelector("img").src = res.picture;
        const rooms = (res.rooms || []).map((r) => r.name).filter(Boolean);
        box.querySelector(".lb-info").textContent = [b.dataset.name, rooms.length ? `${rooms.length} rooms: ${rooms.join(", ")}` : "",
          "tap to close"].filter(Boolean).join("   ·   ");
      } catch (e) { box.querySelector(".lb-info").textContent = "Could not draw the map: " + (e.message || e); }
    });
    pane.querySelectorAll("[data-lock]").forEach((b) => b.onclick = async () => {
      b.disabled = true;
      const lock = b.dataset.to === "1";
      if (await this._call(DOMAIN, "set_map_lock", { map: b.dataset.lock, locked: lock }, { entity_id: this._robot }))
        this._pendMap(pane, b.dataset.lock, lock ? "Locking..." : "Unlocking...", (m) => !m || m.locked === lock);
      else b.disabled = false;
    });
    // Renamed in place: a text box in the row (no browser prompt, which app webviews may not show).
    pane.querySelectorAll("[data-rename]").forEach((b) => b.onclick = () => {
      const row = b.closest(".row"), id = b.dataset.rename, old = b.dataset.name;
      row.innerHTML = `<div class="main"><input class="rename" maxlength="32" aria-label="New map name" value="${esc(old)}">
        <div class="s">Up to 32 characters. Automations that name this map will need the new name.</div></div>
        <button class="btn primary" data-act="save">Save</button><button class="btn" data-act="cancel">Cancel</button>`;
      const input = row.querySelector("input"), save = row.querySelector("[data-act=save]");
      const done = () => { input.blur(); this._paneSettings(pane); };
      const submit = async () => {
        const name = input.value.trim();
        if (!name || name === old) return done();
        save.disabled = true;
        if (await this._call(DOMAIN, "rename_map", { map: id, name }, { entity_id: this._robot })) {
          input.blur();
          return this._pendMap(pane, id, `Renaming to "${name}"...`, (m) => !m || m.name === name);
        }
        save.disabled = false; input.focus();
      };
      save.onclick = submit;
      row.querySelector("[data-act=cancel]").onclick = done;
      input.onkeydown = (e) => { if (e.key === "Enter") submit(); else if (e.key === "Escape") done(); };
      input.focus(); input.select();
    });
    // Copied to a new map beside it, to edit without touching the original; switch to it with the
    // map selector and back the same way.
    pane.querySelectorAll("[data-copy]").forEach((b) => b.onclick = () => {
      const row = b.closest(".row"), id = b.dataset.copy, old = b.dataset.name;
      row.innerHTML = `<div class="main"><input class="rename" maxlength="32" aria-label="Name for the copy" value="${esc(`${old} copy`.slice(0, 32))}">
        <div class="s copynote">A new map with the same rooms, names, no-go zones and furniture. Takes a minute or two: the map is backed up to your TP-Link cloud and restored beside the original, which stays as it is. Docked and idle only.</div></div>
        <button class="btn primary" data-act="save">Copy</button><button class="btn" data-act="cancel">Cancel</button>`;
      const input = row.querySelector("input"), save = row.querySelector("[data-act=save]"), cancel = row.querySelector("[data-act=cancel]");
      const done = () => { input.blur(); this._paneSettings(pane); };
      const submit = async () => {
        const name = input.value.trim();
        if (!name) return input.focus();
        save.disabled = cancel.disabled = input.disabled = true;
        const note = row.querySelector(".copynote");
        note.textContent = `Copying to "${name}". This takes a minute or two; keep the robot docked.`;
        const bar = this._jobBar(note.parentElement, "copy", "Starting the copy");
        try {
          const res = await this._hass.callService(DOMAIN, "copy_map", { map: id, name }, { entity_id: this._robot }, false, true);
          bar.stop();
          const r = (res && res.response) ? res.response : res || {};
          const message = [r.next_steps, r.note].filter(Boolean).join(" ") || `Copied to "${name}".`;
          this.dispatchEvent(new CustomEvent("hass-notification", { detail: { message }, bubbles: true, composed: true }));
          return done();
        } catch (e) {
          bar.stop();
          const message = (e && (e.message || (e.body && e.body.message))) || "The robot rejected that";
          this.dispatchEvent(new CustomEvent("hass-notification", { detail: { message }, bubbles: true, composed: true }));
        }
        if (!row.isConnected) return;
        bar.el.remove();
        row.querySelector(".copynote").textContent = "";
        save.disabled = cancel.disabled = input.disabled = false; input.focus();
      };
      save.onclick = submit;
      cancel.onclick = done;
      input.onkeydown = (e) => { if (e.key === "Enter") submit(); else if (e.key === "Escape") done(); };
      input.focus(); input.select();
    });
    // Deleted only after a second, explicit press in the row.
    pane.querySelectorAll("[data-delete]").forEach((b) => b.onclick = () => {
      const row = b.closest(".row"), id = b.dataset.delete, name = b.dataset.name || `Map ${id}`;
      row.innerHTML = `<div class="main"><div class="t">Delete "${esc(name)}" from the robot?</div>
        <div class="s delnote">Its presets and schedules go with it. It can only come back from a backup (Backups tab).</div></div>
        <button class="btn primary" data-act="del"><ha-icon icon="mdi:delete-outline"></ha-icon>Delete</button><button class="btn" data-act="cancel">Cancel</button>`;
      const del = row.querySelector("[data-act=del]"), cancel = row.querySelector("[data-act=cancel]");
      cancel.onclick = () => this._paneSettings(pane);
      del.onclick = async () => {
        del.disabled = cancel.disabled = true;
        row.querySelector(".delnote").textContent = `Deleting "${name}"...`;
        if (await this._call(DOMAIN, "delete_map", { map: id, confirm: true }, { entity_id: this._robot }))
          return this._pendMap(pane, id, "Deleting...", (m) => !m);
        if (row.isConnected) { del.disabled = cancel.disabled = false; row.querySelector(".delnote").textContent = "Not deleted."; }
      };
      cancel.focus();
    });
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
