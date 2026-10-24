/* Tapo Robot Vacuum dashboard strategy: a whole dashboard from one line of config.
 *
 *   strategy:
 *     type: custom:tapo-rv30
 *
 * Finds every Tapo robot in this Home Assistant and builds, per robot, an overview view
 * (the bundled card with status, a rooms section, maintenance, settings and schedules).
 * Entities are found through the entity registry by device, so renamed entities still work.
 */
const DOMAIN = "tapo_rv30";

function entitiesFor(hass, deviceId) {
  return Object.values(hass.entities || {}).filter((e) => e.device_id === deviceId && !e.hidden);
}
function byDomain(list, domain) { return list.filter((e) => e.entity_id.startsWith(domain + ".")); }
function find(list, needle) { return list.find((e) => e.entity_id.includes(needle)); }
// A URL-safe view path that no other robot's view uses. Accents are dropped ("Café" -> "cafe");
// names with no Latin letters or digits at all fall back to "robot". A purely numeric path would
// be read as a view index, so it gets a prefix too.
function viewPath(name, used) {
  let base = String(name).normalize("NFKD").replace(/[\u0300-\u036f]/g, "").toLowerCase()
    .replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  if (!base || /^\d+$/.test(base)) base = base ? `robot-${base}` : "robot";
  let path = base;
  for (let n = 2; used.has(path); n++) path = `${base}-${n}`;
  used.add(path);
  return path;
}
function title(hass, e) { return (hass.states[e.entity_id] || {}).attributes?.friendly_name || e.entity_id; }

function robotViews(hass, device, used) {
  const ents = entitiesFor(hass, device.id);
  const vac = byDomain(ents, "vacuum")[0];
  if (!vac) return [];
  const sensors = byDomain(ents, "sensor"), switches = byDomain(ents, "switch"), selects = byDomain(ents, "select");
  const buttons = byDomain(ents, "button"), binaries = byDomain(ents, "binary_sensor"), numbers = byDomain(ents, "number");
  const images = byDomain(ents, "image");
  const rooms = (hass.states[vac.entity_id]?.attributes?.rooms) || [];
  const name = device.name_by_user || device.name || "Robot";
  const pick = (list, needles) => needles.map((n) => find(list, n)).filter(Boolean).map((e) => e.entity_id);

  const cards = [
    { type: "custom:tapo-rv30-card", entity: vac.entity_id },
  ];
  if (rooms.length) {
    cards.push({
      type: "grid", columns: 2, square: false, title: "Rooms",
      cards: rooms.map((r) => ({
        type: "button", name: r, icon: "mdi:floor-plan", show_state: false,
        tap_action: { action: "perform-action", perform_action: "tapo_rv30.clean_rooms",
                      target: { entity_id: vac.entity_id }, data: { rooms: [r] } },
      })),
    });
  }
  const presets = buttons.filter((e) => e.entity_id.includes("preset")).map((e) => e.entity_id);
  if (presets.length) cards.push({ type: "entities", title: "Presets", entities: presets });
  const lastClean = find(images, "last_clean");
  if (lastClean) cards.push({ type: "picture-entity", entity: lastClean.entity_id, show_state: false, show_name: true, name: "Last clean" });
  cards.push({
    type: "entities", title: "Status",
    entities: pick(sensors, ["status", "battery", "error", "current_room", "clean_progress", "area_cleaned", "last_clean"])
      .concat(pick(binaries, ["charging", "problem", "mop_attached", "do_not_disturb_active"])),
  });
  const maint = pick(sensors, ["main_brush_remaining", "side_brush_remaining", "filter_remaining", "sensor_remaining", "charge_contacts_remaining"])
    .concat(pick(buttons, ["empty_bin", "reset_main_brush", "reset_side_brush", "reset_filter", "reset_sensor", "reset_charge_contacts", "wash_mop", "dry_mop", "remove_hair"]));
  if (maint.length) cards.push({ type: "entities", title: "Maintenance", entities: maint });
  const settings = selects.map((e) => e.entity_id).concat(switches.map((e) => e.entity_id)).concat(numbers.map((e) => e.entity_id));
  if (settings.length) cards.push({ type: "entities", title: "Settings", entities: settings });
  const sched = find(sensors, "schedules");
  const totals = pick(sensors, ["total_cleans", "total_area", "total_cleaning_time"]);
  if (sched || totals.length) cards.push({ type: "entities", title: "Schedules and totals", entities: [sched?.entity_id].filter(Boolean).concat(totals) });
  return [{ title: name, path: viewPath(name, used), icon: "mdi:robot-vacuum",
            type: "sections", max_columns: 3,
            sections: cards.map((c) => ({ type: "grid", cards: [c] })) }];
}

class TapoRV30DashboardStrategy {
  static async generate(config, hass) {
    const devices = Object.values(hass.devices || {}).filter((d) =>
      (d.identifiers || []).some((i) => i[0] === DOMAIN));
    const used = new Set();
    const views = devices.flatMap((d) => robotViews(hass, d, used));
    if (!views.length) {
      return { title: "Tapo Vacuum", views: [{ title: "Tapo Vacuum", cards: [{ type: "markdown",
        content: "No Tapo robot vacuum found. Set up the Tapo Robot Vacuum integration first." }] }] };
    }
    return { title: config.title || "Tapo Vacuum", views };
  }
}
if (!customElements.get("ll-strategy-dashboard-tapo-rv30")) customElements.define("ll-strategy-dashboard-tapo-rv30", TapoRV30DashboardStrategy);
