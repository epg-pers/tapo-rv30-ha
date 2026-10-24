/* Tapo Robot Vacuum dashboard strategy: a whole dashboard from one line of config.
 *
 *   strategy:
 *     type: custom:tapo-rv30
 *
 * Finds every Tapo robot in this Home Assistant and builds, per robot, an overview view
 * (the bundled card with status, a rooms section, maintenance, settings and schedules).
 * Entities are found through the entity registry by device, then by translation key or the end
 * of the entity id: a renamed device or friendly name does not matter, but an entity id changed by
 * hand is not found.
 */
const DOMAIN = "tapo_rv30";

function entitiesFor(hass, deviceId) {
  return Object.values(hass.entities || {}).filter((e) => e.device_id === deviceId && !e.hidden);
}
function byDomain(list, domain) { return list.filter((e) => e.entity_id.startsWith(domain + ".")); }
// Translation keys the integration sets, by the entity id suffix they stand in for. A translation
// key does not depend on the entity id at all (one made in another language too); the rest go by suffix.
const TRANSLATION_KEYS = { status: "status", error: "error", current_room: "current_room", schedules: "schedules",
  charging: "charging", problem: "problem" };
const objectId = (e) => e.entity_id.slice(e.entity_id.indexOf(".") + 1);
// An id made from a name the way Home Assistant makes entity ids ("Jarvis Robot" -> "jarvis_robot").
const slug = (n) => String(n || "").normalize("NFKD").replace(/[\u0300-\u036f]/g, "").toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
// One of the device's entities by its exact suffix ("last_clean" is never "last_clean_area"). An id
// <base>_<suffix> wins (bases: the vacuum's object id and the device's name), then the shortest, so
// "status" is the robot's Status and not its Planner Status.
function find(list, suffix, bases) {
  const key = TRANSLATION_KEYS[suffix];
  const byKey = key && list.find((e) => e.translation_key === key);
  if (byKey) return byKey;
  const exact = list.find((e) => bases.some((b) => objectId(e) === `${b}_${suffix}`));
  if (exact) return exact;
  return list.filter((e) => objectId(e).endsWith(`_${suffix}`)).sort((a, b) => objectId(a).length - objectId(b).length)[0];
}
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
  // What the device's entity ids start with: the vacuum's own, or the device name they were made from.
  const bases = [objectId(vac), slug(device.name_by_user), slug(device.name)].filter(Boolean);
  const pick = (list, suffixes) => suffixes.map((n) => find(list, n, bases)).filter(Boolean).map((e) => e.entity_id);

  const cards = [
    { type: "custom:tapo-rv30-card", entity: vac.entity_id },
  ];
  // The map camera knows each room's id: cleaning by id works for unnamed rooms and for two rooms
  // with the same name. Without it (map not read yet) the vacuum's room names are all there is.
  const cams = byDomain(ents, "camera").map((e) => hass.states[e.entity_id]?.attributes).filter(Boolean);
  const cam = cams.find((a) => Array.isArray(a.room_geometry) && a.room_geometry.length && a.room_geometry.every((r) => r && r.id != null));
  const geom = cam ? cam.room_geometry : [];
  // Room ids restart on every map, and this dashboard does not follow a floor switch: sent with the
  // map they came from, a button left over from another floor fails clearly instead of cleaning
  // the room with the same id (or name) on this one. The vacuum's room names are the camera's map.
  const mapId = (cam ? [cam] : cams).map((a) => a.map_id).find(Number.isInteger);
  const onMap = (data) => (mapId != null ? { ...data, map_id: mapId } : data);
  const roomButtons = geom.length
    ? geom.map((g) => ({ name: g.name || `Room ${g.id}`, data: onMap({ room_ids: [g.id] }) }))
    : rooms.map((r) => ({ name: r, data: onMap({ rooms: [r] }) }));
  if (roomButtons.length) {
    cards.push({
      type: "grid", columns: 2, square: false, title: "Rooms",
      cards: roomButtons.map((b) => ({
        type: "button", name: b.name, icon: "mdi:floor-plan", show_state: false,
        tap_action: { action: "perform-action", perform_action: "tapo_rv30.clean_rooms",
                      target: { entity_id: vac.entity_id }, data: b.data },
      })),
    });
  }
  // Preset buttons are named "Preset <name>", so their ids are <base>_preset_<name>.
  const presets = buttons.filter((e) => e.translation_key === "preset" || bases.some((b) => objectId(e).startsWith(`${b}_preset_`)))
    .map((e) => e.entity_id);
  if (presets.length) cards.push({ type: "entities", title: "Presets", entities: presets });
  const lastClean = find(images, "last_clean_map", bases);
  if (lastClean) cards.push({ type: "picture-entity", entity: lastClean.entity_id, show_state: false, show_name: true, name: "Last clean" });
  cards.push({
    type: "entities", title: "Status",
    entities: pick(sensors, ["status", "battery", "error", "current_room", "clean_progress", "last_clean_area", "last_clean"])
      .concat(pick(binaries, ["charging", "problem", "mop_attached", "do_not_disturb_active"])),
  });
  const maint = pick(sensors, ["main_brush_remaining", "side_brush_remaining", "filter_remaining", "sensor_remaining", "charge_contacts_remaining"])
    .concat(pick(buttons, ["empty_bin", "reset_main_brush", "reset_side_brush", "reset_filter", "reset_sensor", "reset_charge_contacts", "wash_mop", "dry_mop", "remove_hair"]));
  if (maint.length) cards.push({ type: "entities", title: "Maintenance", entities: maint });
  const settings = selects.map((e) => e.entity_id).concat(switches.map((e) => e.entity_id)).concat(numbers.map((e) => e.entity_id));
  if (settings.length) cards.push({ type: "entities", title: "Settings", entities: settings });
  const sched = find(sensors, "schedules", bases);
  const totals = pick(sensors, ["total_cleans", "total_area_cleaned", "total_cleaning_time"]);
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
