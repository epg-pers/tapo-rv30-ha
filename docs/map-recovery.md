# Map backup and recovery

Robot maps are easy to lose - a bad re-map, an accidental delete, a firmware hiccup - and
losing one means redrawing every room, no-go zone and setting by hand. This integration gives
you three safety nets, all run from Home Assistant, none of which need you at a PC.

For the protocol detail behind all of this - how backup and restore actually work on the robot -
see the [protocol notes](protocol.md).

## What a map is made of

A map has two layers:

- **The shape** (the walls and obstacles the robot sensed). The robot builds this with its
  own mapping; nothing, not even the Tapo app, can write it from scratch. If it's lost, the
  robot re-maps it by cleaning the floor again.
- **Everything on top**: your **rooms and their names**, **no-go zones**, **virtual walls** and
  **carpets**. These are yours.

## Restore a whole map backup to the robot

`tapo_rv30.restore_map_backup` puts a backed-up map - shape and all - back on the robot,
entirely on your own network. Home Assistant serves a backup it already holds (see *Keep local
copies* below) on your LAN, and the robot downloads it and applies it with its own recovery. No
app, no cloud round-trip.

```yaml
service: tapo_rv30.restore_map_backup
data:
  map: Downstairs     # the map to restore (name or id)
  confirm: true
target:
  entity_id: vacuum.jarvis
```

The robot must be **docked and idle**. By default the newest backup held for that map is used;
pass `file:` to pick a specific one.

**The one requirement:** the robot has to reach Home Assistant **directly on your LAN**. Its
firmware uses a bare-bones HTTP client that needs a plain response with a correct
`Content-Length`, which Home Assistant sends when the robot talks to it directly. If you put the
robot onto Home Assistant's *external* address and that goes through a reverse proxy (nginx,
Caddy, Cloudflare Tunnel, and so on), the proxy re-chunks the response and the robot's download
stalls and the restore fails. The service picks Home Assistant's direct LAN address
automatically; only set `base_url` if it guesses wrong (for example a multi-homed host).

If the robot can't reach Home Assistant on the LAN at all, `use_cloud_url: true` falls back to
handing the robot the backup's own TP-Link URL instead (this needs your TP-Link login, as for
`fetch_cloud_map_backups`).

## Save and re-apply your map setup

A lighter-weight recovery for the common case - you re-mapped a floor and just want your zones
and room names back - without touching the map shape at all.

- **Save:** `tapo_rv30.save_map_setup` (or the **Save setup** button on the sidebar page's
  **Maintenance** tab) snapshots the current map's no-go zones, virtual walls, carpets and room
  names to `config/tapo_rv30/map_setups/<map_id>.json`. A good habit is an automation that
  saves after any map edit.
- **Restore:** `tapo_rv30.apply_map_setup` (or **Restore setup**) writes the saved setup back
  onto the map. The robot must be docked and idle. Because zones and walls are stored in
  real-world coordinates, they drop back into exactly the right places.

### Recovering a floor the robot re-mapped

When the robot re-maps a floor it creates a **new map with a new id**, so the new map won't have
a snapshot of its own. Point `apply_map_setup` at the old map's saved setup with `source_map`:

```yaml
service: tapo_rv30.apply_map_setup
data:
  source_map: Downstairs   # the name (or id) of the map you saved before
  confirm: true
target:
  entity_id: vacuum.jarvis
```

What transfers: no-go zones, virtual walls, carpets, room names. What doesn't: the exact room
*boundaries* (the robot re-segments the new shape) and per-room suction/water/passes (those are
preset-only on RV30 1.3.3 firmware).

## Keep local copies of your cloud backups

The Tapo app's "back up map" uploads your map to TP-Link's cloud. `tapo_rv30.fetch_cloud_map_backups`
logs in to your TP-Link account and downloads those backups into `config/tapo_rv30/map_backups`,
so you keep a copy even if TP-Link's is ever lost - and so `restore_map_backup` has something to
serve. The first run may e-mail you a two-step code; run it again with `verification_code` set to
it, and Home Assistant becomes a trusted device.

Keep in mind: **deleting a map in the app deletes its cloud backup too**, and `restore_map_backup`
recovers *into* a map your account still has (the robot won't recreate a map id it has deleted).
So fetch your backups ahead of time, and keep the map around.

## What's recoverable, at a glance

| Layer | Lost when | Put back by |
| --- | --- | --- |
| Map shape (walls) | re-map, map delete | `restore_map_backup` (from a backup), or the robot re-mapping |
| Rooms' names | re-map, edit | `restore_map_backup`, or `apply_map_setup` |
| No-go zones, virtual walls, carpets | re-map, edit, delete | `restore_map_backup`, or `apply_map_setup` (exact positions) |
| Room boundaries | re-map | `restore_map_backup`; approximate via `apply_map_setup` |
| Per-room suction/water/passes | - | preset-only on 1.3.3 firmware |
