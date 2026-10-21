/*
 * Tapo RV30 card. Shipped and registered by the tapo_rv30 integration; no
 * HACS frontend install needed.
 *
 *   type: custom:tapo-rv30-card
 *   entity: vacuum.robot
 *
 * Tap rooms on the map to select them and clean, or switch to zone mode and
 * drag a rectangle. Everything else (status, presets, controls) is found from
 * the vacuum's device automatically.
 */

const CARD_VERSION = "0.10.0";
const ROOM_COLORS = ["#ffb3ba", "#bae1ff", "#baffc9", "#ffffba", "#dcbaff", "#ffdcba", "#baffff"];

const ICONS = {
  start: "mdi:play", pause: "mdi:pause", stop: "mdi:stop", dock: "mdi:home-import-outline",
  locate: "mdi:map-marker-radius", bin: "mdi:delete-empty", rooms: "mdi:floor-plan",
  zone: "mdi:vector-square", clear: "mdi:close", preset: "mdi:play-box-multiple",
  battery: "mdi:battery", charging: "mdi:battery-charging", robot: "mdi:robot-vacuum",
  alert: "mdi:alert-circle", room: "mdi:map-marker",
};

const STYLE = `
:host { display: block; }
[hidden] { display: none !important; }
ha-card { overflow: hidden; }
.head { display: flex; align-items: center; gap: 14px; padding: 16px 16px 8px; }
.avatar { position: relative; width: 48px; height: 48px; border-radius: 50%; flex: none;
  display: flex; align-items: center; justify-content: center;
  background: color-mix(in srgb, var(--primary-color) 18%, transparent); color: var(--primary-color); }
.avatar ha-icon { --mdc-icon-size: 26px; }
.avatar.active::after { content: ""; position: absolute; inset: -4px; border-radius: 50%;
  border: 2px solid var(--primary-color); opacity: .6; animation: pulse 1.6s ease-out infinite; }
@keyframes pulse { 0% { transform: scale(.9); opacity: .7 } 100% { transform: scale(1.35); opacity: 0 } }
.title { flex: 1; min-width: 0; }
.name { font-size: 1.15em; font-weight: 500; color: var(--primary-text-color); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.sub { font-size: .85em; color: var(--secondary-text-color); display: flex; gap: 6px; align-items: center; flex-wrap: wrap; }
.sub .dot { opacity: .5; }
.battery { display: flex; align-items: center; gap: 4px; font-size: .9em; color: var(--secondary-text-color); white-space: nowrap; }
.battery ha-icon { --mdc-icon-size: 20px; }
.battery.low { color: var(--error-color, #db4437); }
.progress { height: 4px; margin: 0 16px 6px; border-radius: 2px; background: color-mix(in srgb, var(--primary-color) 15%, transparent); overflow: hidden; }
.progress > div { height: 100%; background: var(--primary-color); transition: width .6s ease; }
.banner { margin: 4px 16px 8px; padding: 8px 12px; border-radius: 10px; font-size: .9em; display: flex; gap: 8px; align-items: center;
  background: color-mix(in srgb, var(--error-color, #db4437) 14%, transparent); color: var(--error-color, #db4437); }
.mapwrap { position: relative; margin: 6px 12px; border-radius: 14px; overflow: hidden;
  background: color-mix(in srgb, var(--primary-text-color) 5%, transparent); }
canvas { display: block; width: 100%; height: auto; touch-action: none; cursor: crosshair; }
.hint { position: absolute; left: 10px; top: 10px; font-size: .78em; padding: 4px 9px; border-radius: 999px;
  background: color-mix(in srgb, var(--card-background-color) 75%, transparent); color: var(--secondary-text-color);
  backdrop-filter: blur(6px); pointer-events: none; }
.tools { position: absolute; right: 10px; top: 10px; display: flex; gap: 6px; }
.tools button { width: 36px; height: 36px; border-radius: 10px; border: none; cursor: pointer; display: flex; align-items: center; justify-content: center;
  background: color-mix(in srgb, var(--card-background-color) 80%, transparent); color: var(--secondary-text-color); backdrop-filter: blur(6px); }
.tools button.on { background: var(--primary-color); color: var(--text-primary-color, #fff); }
.tools button ha-icon { --mdc-icon-size: 20px; }
.go { position: absolute; left: 50%; bottom: 12px; transform: translateX(-50%); display: flex; align-items: center; gap: 8px;
  padding: 10px 18px; border: none; border-radius: 999px; cursor: pointer; font-size: .95em; font-weight: 500;
  background: var(--primary-color); color: var(--text-primary-color, #fff); box-shadow: 0 6px 18px rgba(0,0,0,.25); white-space: nowrap; max-width: 90%; overflow: hidden; text-overflow: ellipsis; }
.go ha-icon { --mdc-icon-size: 20px; flex: none; }
.chips { display: flex; gap: 8px; padding: 8px 16px 4px; overflow-x: auto; scrollbar-width: none; }
.chips::-webkit-scrollbar { display: none; }
.chip { flex: none; display: flex; align-items: center; gap: 6px; padding: 7px 12px; border-radius: 999px; cursor: pointer; border: none; font-size: .88em;
  background: color-mix(in srgb, var(--primary-text-color) 7%, transparent); color: var(--primary-text-color); }
.chip:hover { background: color-mix(in srgb, var(--primary-color) 18%, transparent); }
.chip ha-icon { --mdc-icon-size: 18px; color: var(--primary-color); }
.controls { display: flex; justify-content: space-around; padding: 10px 12px 14px; }
.ctl { display: flex; flex-direction: column; align-items: center; gap: 4px; background: none; border: none; cursor: pointer; color: var(--secondary-text-color); font-size: .72em; min-width: 56px; }
.ctl .ring { width: 44px; height: 44px; border-radius: 14px; display: flex; align-items: center; justify-content: center;
  background: color-mix(in srgb, var(--primary-text-color) 7%, transparent); transition: background .15s; }
.ctl:hover .ring { background: color-mix(in srgb, var(--primary-color) 20%, transparent); }
.ctl.primary .ring { background: var(--primary-color); color: var(--text-primary-color, #fff); }
.ctl ha-icon { --mdc-icon-size: 24px; }
.ctl[disabled] { opacity: .35; pointer-events: none; }
.empty { padding: 24px; text-align: center; color: var(--secondary-text-color); }
`;

class TapoRV30Card extends HTMLElement {
  static getConfigElement() { return document.createElement("tapo-rv30-card-editor"); }
  static getStubConfig(hass) {
    const vac = Object.keys(hass.states).find((id) => id.startsWith("vacuum.") && hass.states[id].attributes.integration === "tapo_rv30")
      || Object.keys(hass.states).find((id) => id.startsWith("vacuum."));
    return { entity: vac || "vacuum.robot" };
  }

  constructor() {
    super();
    this.attachShadow({ mode: "open" });
    this._selected = new Set();
    this._mode = "rooms";
    this._zone = null;          // {x0,y0,x1,y1} in canvas px
    this._mask = null;          // {w,h,data(Uint8ClampedArray)}
    this._maskKey = null;
    this._img = null; this._imgKey = null;
    this._raf = null;
  }

  setConfig(config) {
    if (!config || !config.entity) throw new Error("Set 'entity' to your vacuum (vacuum.xxx)");
    this._config = { show_presets: true, show_controls: true, ...config };
    this._related = null;
    this._build();
  }

  getCardSize() { return 8; }

  set hass(hass) {
    const first = !this._hass;
    this._hass = hass;
    if (!this._related) this._related = this._findRelated();
    const sig = this._signature();
    if (first || sig !== this._sig) { this._sig = sig; this._render(); }
    this._loadImage();
    this._loadMask();
  }

  // ---- entity discovery -----------------------------------------------------------
  _findRelated() {
    const hass = this._hass, vac = this._config.entity;
    const reg = hass.entities || {};
    const dev = reg[vac] && reg[vac].device_id;
    let ids = [];
    if (dev) ids = Object.keys(reg).filter((id) => reg[id].device_id === dev);
    if (!ids.length) {                       // registry not available: guess from the object id
      const base = vac.split(".")[1];
      ids = Object.keys(hass.states).filter((id) => id.split(".")[1].startsWith(base));
    }
    const find = (prefix, suffix) => ids.find((id) => id.startsWith(prefix) && (!suffix || id.endsWith(suffix)));
    return {
      image: this._config.image_entity || find("image."),
      camera: this._config.camera_entity || find("camera."),
      battery: find("sensor.", "_battery"),
      status: find("sensor.", "_status"),
      room: find("sensor.", "_current_room"),
      progress: find("sensor.", "_clean_progress"),
      problem: find("binary_sensor.", "_problem"),
      charging: find("binary_sensor.", "_charging"),
      bin: find("button.", "_empty_bin"),
      presets: ids.filter((id) => id.startsWith("button.") && id.includes("_preset_")),
    };
  }

  _call(domain, service, data, target) {
    return this._hass.callService(domain, service, data, target).catch((err) => {
      const message = (err && (err.message || err.body && err.body.message)) || String(err);
      this.dispatchEvent(new CustomEvent("hass-notification", { detail: { message }, bubbles: true, composed: true }));
    });
  }

  _st(id) { return id && this._hass.states[id]; }
  _val(id, fallback) { const s = this._st(id); return s ? s.state : fallback; }

  _signature() {
    const r = this._related, h = this._hass;
    const ids = [this._config.entity, r.image, r.camera, r.battery, r.status, r.room, r.progress, r.problem, r.charging, ...r.presets];
    return ids.map((id) => { const s = h.states[id]; return s ? s.last_updated + s.state : "-"; }).join("|");
  }

  // ---- DOM ----------------------------------------------------------------------------
  _build() {
    const root = this.shadowRoot;
    root.innerHTML = `<style>${STYLE}</style><ha-card>
      <div class="head">
        <div class="avatar"><ha-icon icon="${ICONS.robot}"></ha-icon></div>
        <div class="title"><div class="name"></div><div class="sub"></div></div>
        <div class="battery"><ha-icon icon="${ICONS.battery}"></ha-icon><span></span></div>
      </div>
      <div class="progress" hidden><div></div></div>
      <div class="banner" hidden><ha-icon icon="${ICONS.alert}"></ha-icon><span></span></div>
      <div class="mapwrap">
        <canvas></canvas>
        <div class="hint"></div>
        <div class="tools">
          <button class="t-rooms" title="Select rooms"><ha-icon icon="${ICONS.rooms}"></ha-icon></button>
          <button class="t-zone" title="Draw a zone"><ha-icon icon="${ICONS.zone}"></ha-icon></button>
          <button class="t-clear" title="Clear" hidden><ha-icon icon="${ICONS.clear}"></ha-icon></button>
        </div>
        <button class="go" hidden><ha-icon icon="${ICONS.start}"></ha-icon><span></span></button>
      </div>
      <div class="chips"></div>
      <div class="controls"></div>
    </ha-card>`;
    this._el = {
      name: root.querySelector(".name"), sub: root.querySelector(".sub"), avatar: root.querySelector(".avatar"),
      battery: root.querySelector(".battery"), progress: root.querySelector(".progress"),
      banner: root.querySelector(".banner"), canvas: root.querySelector("canvas"), hint: root.querySelector(".hint"),
      tRooms: root.querySelector(".t-rooms"), tZone: root.querySelector(".t-zone"), tClear: root.querySelector(".t-clear"),
      go: root.querySelector(".go"), chips: root.querySelector(".chips"), controls: root.querySelector(".controls"),
      mapwrap: root.querySelector(".mapwrap"),
    };
    this._el.tRooms.onclick = () => this._setMode("rooms");
    this._el.tZone.onclick = () => this._setMode("zone");
    this._el.tClear.onclick = () => this._clearSelection();
    this._el.go.onclick = () => this._go();
    const c = this._el.canvas;
    c.addEventListener("pointerdown", (e) => this._down(e));
    c.addEventListener("pointermove", (e) => this._move(e));
    c.addEventListener("pointerup", (e) => this._up(e));
    c.addEventListener("pointercancel", () => { this._drag = null; });
    this._setMode("rooms");
  }

  _render() {
    const h = this._hass, r = this._related, vac = this._st(this._config.entity);
    if (!vac) { this.shadowRoot.querySelector("ha-card").innerHTML = `<div class="empty">${this._config.entity} not found</div>`; return; }
    const name = this._config.name || vac.attributes.friendly_name || this._config.entity;
    const state = vac.state;
    const status = this._val(r.status, state);
    const room = vac.attributes.current_room || this._val(r.room, null);
    this._el.name.textContent = name;
    this._el.sub.innerHTML = `<span>${status}</span>` + (room && room !== "unknown" ? `<span class="dot">&middot;</span><ha-icon icon="${ICONS.room}" style="--mdc-icon-size:14px"></ha-icon><span>${room}</span>` : "");
    this._el.avatar.classList.toggle("active", state === "cleaning" || state === "returning");

    const batt = parseInt(this._val(r.battery, ""), 10);
    const charging = this._val(r.charging, "off") === "on" || state === "docked";
    this._el.battery.querySelector("span").textContent = isNaN(batt) ? "" : `${batt}%`;
    this._el.battery.querySelector("ha-icon").setAttribute("icon", charging ? ICONS.charging : this._batteryIcon(batt));
    this._el.battery.classList.toggle("low", !isNaN(batt) && batt <= 20 && !charging);

    const pct = parseInt(this._val(r.progress, ""), 10);
    const showProgress = state === "cleaning" && !isNaN(pct);
    this._el.progress.hidden = !showProgress;
    if (showProgress) this._el.progress.firstElementChild.style.width = `${pct}%`;

    const problem = this._st(r.problem);
    const err = problem && problem.state === "on";
    this._el.banner.hidden = !err;
    if (err) this._el.banner.querySelector("span").textContent = problem.attributes.error || "The vacuum reports a problem";

    this._renderChips();
    this._renderControls(state);
    this._draw();
  }

  _batteryIcon(p) {
    if (isNaN(p)) return ICONS.battery;
    const step = Math.max(10, Math.min(100, Math.round(p / 10) * 10));
    return step === 100 ? "mdi:battery" : `mdi:battery-${step}`;
  }

  _renderChips() {
    const el = this._el.chips, r = this._related;
    if (!this._config.show_presets || !r.presets.length) { el.hidden = true; return; }
    el.hidden = false;
    el.innerHTML = "";
    for (const id of r.presets) {
      const s = this._st(id); if (!s) continue;
      const label = (s.attributes.friendly_name || id).replace(/^.*?Preset\s*/i, "");
      const b = document.createElement("button"); b.className = "chip";
      b.innerHTML = `<ha-icon icon="${ICONS.preset}"></ha-icon><span>${label}</span>`;
      b.title = (s.attributes.rooms || []).join(", ");
      b.onclick = () => this._call("button", "press", {}, { entity_id: id });
      el.appendChild(b);
    }
  }

  _renderControls(state) {
    const el = this._el.controls, r = this._related;
    if (!this._config.show_controls) { el.hidden = true; return; }
    const cleaning = state === "cleaning", paused = state === "paused", docked = state === "docked";
    const items = [
      cleaning ? { k: "pause", i: ICONS.pause, l: "Pause", svc: "pause" } : { k: "start", i: ICONS.start, l: paused ? "Resume" : "Start", svc: "start", primary: !cleaning },
      { k: "stop", i: ICONS.stop, l: "Stop", svc: "stop", dis: !(cleaning || paused) },
      { k: "dock", i: ICONS.dock, l: "Dock", svc: "return_to_base", dis: docked },
      { k: "locate", i: ICONS.locate, l: "Locate", svc: "locate" },
    ];
    if (r.bin) items.push({ k: "bin", i: ICONS.bin, l: "Empty bin", btn: r.bin, dis: !docked });
    el.innerHTML = "";
    for (const it of items) {
      const b = document.createElement("button"); b.className = "ctl" + (it.primary ? " primary" : "");
      if (it.dis) b.setAttribute("disabled", "");
      b.innerHTML = `<div class="ring"><ha-icon icon="${it.i}"></ha-icon></div><span>${it.l}</span>`;
      b.onclick = () => it.btn ? this._call("button", "press", {}, { entity_id: it.btn })
                              : this._call("vacuum", it.svc, {}, { entity_id: this._config.entity });
      el.appendChild(b);
    }
  }

  // ---- map image + mask ------------------------------------------------------------------
  _mapAttrs() {
    const cam = this._st(this._related.camera);
    return cam ? cam.attributes : {};
  }

  _loadImage() {
    const r = this._related;
    const img = this._st(r.image), cam = this._st(r.camera);
    const src = img ? img.attributes.entity_picture : (cam ? cam.attributes.entity_picture : null);
    if (!src) return;
    const key = src + "|" + (img ? img.state : cam.last_updated);
    if (key === this._imgKey) return;
    this._imgKey = key;
    const im = new Image();
    im.onload = () => { this._img = im; this._draw(); };
    im.src = src.startsWith("http") ? src : this._hass.hassUrl(src);
  }

  async _loadMask() {
    const url = this._mapAttrs().rooms_mask_url;
    if (!url || url === this._maskKey) return;
    this._maskKey = url;
    try {
      const resp = await this._hass.fetchWithAuth(url);
      const blob = await resp.blob();
      const bmp = await createImageBitmap(blob);
      const c = document.createElement("canvas"); c.width = bmp.width; c.height = bmp.height;
      const ctx = c.getContext("2d", { willReadFrequently: true });
      ctx.drawImage(bmp, 0, 0);
      this._mask = { w: bmp.width, h: bmp.height, data: ctx.getImageData(0, 0, bmp.width, bmp.height).data };
      this._draw();
    } catch (e) {
      this._mask = null;
    }
  }

  _roomAt(cx, cy) {
    const m = this._mask, c = this._el.canvas;
    if (!m) return null;
    const gx = Math.floor(cx / c.width * m.w), gy = Math.floor(cy / c.height * m.h);
    if (gx < 0 || gy < 0 || gx >= m.w || gy >= m.h) return null;
    const v = m.data[(gy * m.w + gx) * 4];
    if (v === 0 || v === 127 || v === 255) return null;
    return v;
  }

  _roomName(id) {
    const g = (this._mapAttrs().room_geometry || []).find((r) => r.id === id);
    return g ? (g.name || `Room ${id}`) : `Room ${id}`;
  }

  _roomColor(id) {
    const ids = (this._mapAttrs().room_geometry || []).map((r) => r.id).sort((a, b) => a - b);
    return ROOM_COLORS[Math.max(0, ids.indexOf(id)) % ROOM_COLORS.length];
  }

  _draw() {
    const c = this._el.canvas, img = this._img;
    if (!img) return;
    if (c.width !== img.naturalWidth || c.height !== img.naturalHeight) { c.width = img.naturalWidth; c.height = img.naturalHeight; }
    const ctx = c.getContext("2d");
    ctx.clearRect(0, 0, c.width, c.height);
    ctx.drawImage(img, 0, 0);
    if (this._selected.size && this._mask) this._drawSelection(ctx);
    if (this._zone) {
      const z = this._zone, x = Math.min(z.x0, z.x1), y = Math.min(z.y0, z.y1), w = Math.abs(z.x1 - z.x0), h = Math.abs(z.y1 - z.y0);
      ctx.fillStyle = "rgba(40,110,220,.22)"; ctx.fillRect(x, y, w, h);
      ctx.strokeStyle = "rgba(40,110,220,.95)"; ctx.lineWidth = 3; ctx.setLineDash([8, 6]); ctx.strokeRect(x, y, w, h); ctx.setLineDash([]);
    }
    this._drawRobot(ctx);
  }

  _drawSelection(ctx) {
    const m = this._mask, c = this._el.canvas;
    const ov = document.createElement("canvas"); ov.width = m.w; ov.height = m.h;
    const octx = ov.getContext("2d"); const id = octx.createImageData(m.w, m.h);
    const sel = {}; for (const r of this._selected) { const col = this._roomColor(r); sel[r] = [parseInt(col.slice(1, 3), 16), parseInt(col.slice(3, 5), 16), parseInt(col.slice(5, 7), 16)]; }
    for (let i = 0; i < m.w * m.h; i++) {
      const v = m.data[i * 4], col = sel[v];
      if (col) { id.data[i * 4] = 40; id.data[i * 4 + 1] = 110; id.data[i * 4 + 2] = 220; id.data[i * 4 + 3] = 120; }
    }
    octx.putImageData(id, 0, 0);
    ctx.imageSmoothingEnabled = false;
    ctx.drawImage(ov, 0, 0, c.width, c.height);
    ctx.imageSmoothingEnabled = true;
    // outline + label
    const g = this._mapAttrs().room_geometry || [];
    for (const r of g) if (this._selected.has(r.id)) {
      ctx.fillStyle = "rgba(255,255,255,.92)"; ctx.strokeStyle = "rgba(0,0,0,.6)"; ctx.lineWidth = 3;
      ctx.font = "bold 15px sans-serif"; ctx.textAlign = "center"; ctx.textBaseline = "middle";
      ctx.strokeText("✓ " + r.name, r.centre[0], r.centre[1]); ctx.fillText("✓ " + r.name, r.centre[0], r.centre[1]);
    }
  }

  _mmToPx(xmm, ymm) {
    const g = this._mapAttrs().map_geometry; if (!g) return null;
    const s = g.scale_px_per_cell, res = g.resolution_mm, [ox, oy] = g.real_origin_mm, gh = g.grid_size[1];
    return [((xmm - ox) / res) * s + s / 2, (gh - 1 - (ymm - oy) / res) * s + s / 2];
  }

  _pxToMm(x, y) {
    const g = this._mapAttrs().map_geometry; if (!g) return null;
    const s = g.scale_px_per_cell, res = g.resolution_mm, [ox, oy] = g.real_origin_mm, gh = g.grid_size[1];
    return [Math.round(ox + ((x - s / 2) / s) * res), Math.round(oy + (gh - 1 - (y - s / 2) / s) * res)];
  }

  _drawRobot(ctx) {
    const vac = this._st(this._config.entity);
    const pos = vac && vac.attributes.position_mm;
    if (!pos || pos[0] == null) return;
    const p = this._mmToPx(pos[0], pos[1]); if (!p) return;
    const active = vac.state === "cleaning" || vac.state === "returning";
    if (active) {
      const t = (Date.now() % 1600) / 1600;
      ctx.beginPath(); ctx.arc(p[0], p[1], 8 + t * 14, 0, Math.PI * 2);
      ctx.strokeStyle = `rgba(0,180,255,${0.7 * (1 - t)})`; ctx.lineWidth = 3; ctx.stroke();
      if (!this._raf) this._raf = requestAnimationFrame(() => { this._raf = null; this._draw(); });
    }
  }

  // ---- interaction -----------------------------------------------------------------------
  _canvasPoint(e) {
    const c = this._el.canvas, b = c.getBoundingClientRect();
    return [(e.clientX - b.left) * c.width / b.width, (e.clientY - b.top) * c.height / b.height];
  }

  _down(e) {
    e.preventDefault();
    const [x, y] = this._canvasPoint(e);
    if (this._mode === "zone") { this._drag = { x0: x, y0: y }; this._zone = { x0: x, y0: y, x1: x, y1: y }; this._el.canvas.setPointerCapture(e.pointerId); }
    else this._tapStart = [x, y];
  }

  _move(e) {
    if (this._mode !== "zone" || !this._drag) return;
    const [x, y] = this._canvasPoint(e);
    this._zone = { x0: this._drag.x0, y0: this._drag.y0, x1: x, y1: y };
    this._draw();
  }

  _up(e) {
    const [x, y] = this._canvasPoint(e);
    if (this._mode === "zone") {
      if (this._drag) { this._drag = null; if (Math.abs(this._zone.x1 - this._zone.x0) < 6 || Math.abs(this._zone.y1 - this._zone.y0) < 6) this._zone = null; }
    } else if (this._tapStart && Math.hypot(x - this._tapStart[0], y - this._tapStart[1]) < 10) {
      const id = this._roomAt(x, y);
      if (id != null) { if (this._selected.has(id)) this._selected.delete(id); else this._selected.add(id); }
    }
    this._tapStart = null;
    this._updateTools();
    this._draw();
  }

  _setMode(mode) {
    this._mode = mode;
    this._el.tRooms.classList.toggle("on", mode === "rooms");
    this._el.tZone.classList.toggle("on", mode === "zone");
    this._el.hint.textContent = mode === "zone" ? "Drag a rectangle to clean" : "Tap rooms to select";
    this._updateTools();
    this._draw();
  }

  _clearSelection() { this._selected.clear(); this._zone = null; this._updateTools(); this._draw(); }

  _updateTools() {
    const go = this._el.go;
    if (this._mode === "rooms" && this._selected.size) {
      const names = [...this._selected].map((id) => this._roomName(id));
      go.hidden = false; go.querySelector("span").textContent = `Clean ${names.join(", ")}`;
    } else if (this._mode === "zone" && this._zone) {
      go.hidden = false; go.querySelector("span").textContent = "Clean this zone";
    } else go.hidden = true;
    this._el.tClear.hidden = !(this._selected.size || this._zone);
  }

  _go() {
    const target = { entity_id: this._config.entity };
    if (this._mode === "rooms" && this._selected.size) {
      const rooms = [...this._selected].map((id) => this._roomName(id));
      this._call("tapo_rv30", "clean_rooms", { rooms }, target);
    } else if (this._mode === "zone" && this._zone) {
      const z = this._zone, a = this._pxToMm(Math.min(z.x0, z.x1), Math.max(z.y0, z.y1)), b = this._pxToMm(Math.max(z.x0, z.x1), Math.min(z.y0, z.y1));
      if (!a || !b) return;
      this._call("tapo_rv30", "clean_zone", { zones: [[a[0], a[1], b[0], b[1]]] }, target);
    }
    this._clearSelection();
  }
}

class TapoRV30CardEditor extends HTMLElement {
  setConfig(config) { this._config = config; this._render(); }
  set hass(hass) { this._hass = hass; this._render(); }
  _render() {
    if (!this._hass || !this._config) return;
    if (!this._form) {
      this._form = document.createElement("ha-form");
      this._form.schema = [
        { name: "entity", required: true, selector: { entity: { domain: "vacuum" } } },
        { name: "name", selector: { text: {} } },
        { name: "show_presets", selector: { boolean: {} } },
        { name: "show_controls", selector: { boolean: {} } },
      ];
      this._form.computeLabel = (s) => ({ entity: "Vacuum", name: "Name (optional)", show_presets: "Show presets", show_controls: "Show controls" }[s.name] || s.name);
      this._form.addEventListener("value-changed", (e) => {
        this._config = { ...this._config, ...e.detail.value };
        this.dispatchEvent(new CustomEvent("config-changed", { detail: { config: this._config }, bubbles: true, composed: true }));
      });
      this.appendChild(this._form);
    }
    this._form.hass = this._hass;
    this._form.data = { show_presets: true, show_controls: true, ...this._config };
  }
}

if (!customElements.get("tapo-rv30-card")) customElements.define("tapo-rv30-card", TapoRV30Card);
if (!customElements.get("tapo-rv30-card-editor")) customElements.define("tapo-rv30-card-editor", TapoRV30CardEditor);
window.customCards = window.customCards || [];
if (!window.customCards.some((c) => c.type === "tapo-rv30-card")) {
  window.customCards.push({ type: "tapo-rv30-card", name: "Tapo Vacuum", description: "Map with tap-to-clean rooms and zones, presets and controls", preview: true });
}
console.info(`%c TAPO-RV30-CARD %c ${CARD_VERSION} `, "background:#185caa;color:#fff;padding:2px 6px;border-radius:4px 0 0 4px", "background:#1ca9c9;color:#fff;padding:2px 6px;border-radius:0 4px 4px 0");
