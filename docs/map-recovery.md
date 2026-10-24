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

## See your backups before you restore

The sidebar page's **Backups** tab shows every backup Home Assistant holds as a grid of
thumbnails, so you can tell which map a backup is and what it looked like before you put it
back. Tap a thumbnail to see it full size; press **Restore** on one to restore it to the robot
(the same `restore_map_backup` as above, docked and idle). **Fetch from cloud** downloads your
latest TP-Link backups without leaving the page.

Each backup is pictured from the best source it has: the robot's own snapshot image, or - when
there isn't one - the saved map drawn exactly like the live map. The `.bkmap` file itself is
also decoded, so each backup shows its explored floor area, dock position and room count.

## Your map setup is saved automatically

A backup restore brings back the map's shape and room boundaries, but not everything layered on
top: in a real recovery the room names, one of two no-go zones and the furniture came back
missing, and the presets and schedules pointing at the map had gone with it. So the integration
keeps a **map setup snapshot** of each map: room names, no-go zones, virtual walls, carpets,
furniture, and the presets and schedules for that map.

- It is written to `config/tapo_rv30/map_setups/<map_id>.json` **automatically** whenever any of
  that changes, from data the integration already reads. No extra calls to the robot.
- A snapshot that looks like a lost or freshly restored map (no rooms, or fewer named rooms)
  **never replaces a good one**; a warning is logged instead. Every distinct snapshot is also
  kept in `map_setups/history/` (the last 30 per map).
- **Save setup** (`tapo_rv30.save_map_setup`) on the sidebar page's **Maintenance** tab takes one
  right now.

**Put it back:** `tapo_rv30.apply_map_setup` (or **Restore setup** on the Maintenance tab) compares
the map with its snapshot and writes only what is missing or different: room names, zones, walls,
carpets, furniture, and any preset or schedule that no longer exists (schedules are re-pointed at
the recreated presets, which get new ids). Run it with `dry_run: true` first to see exactly what
it would do. The robot must be docked and idle.

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

On a re-mapped floor the rooms are segmented afresh with new ids, so room names and presets only
transfer where the room ids still line up; anything that cannot be placed is listed under
`skipped`. Zones, walls, carpets and furniture are in real-world coordinates and drop back into
exactly the right places.

## If the robot has lost every map

This is the recovery that has been done for real on an RV30 Max Plus, step by step:

1. **Check the Tapo app.** If it still has the map or a cloud backup, restoring there is simplest.
2. **Give the robot any map.** It only accepts a restore onto a map it already has. In the Tapo
   app, run a quick mapping pass (it does not need to be good) and let it dock.
3. **Restore the backup** from the Backups tab, or:
   ```yaml
   service: tapo_rv30.restore_map_backup
   data:
     map: Downstairs        # the lost map's name (from its saved setup) or its id
     confirm: true
   target:
     entity_id: vacuum.jarvis
   ```
   The service uses the throwaway map as the carrier. The robot brings the backup back under the
   lost map's **original id**, so presets, schedules and history that referred to it line up
   again. The response says where it landed and what to do next.
4. **Save it in the Tapo app.** The restored map arrives *unsaved* and unnamed; open it in the
   app, save it with its old name.
5. **Put the layers back:** `apply_map_setup` on that map (`dry_run: true` first if you like).
6. **Delete the throwaway map** in the app.

**What causes it:** this robot has lost every map twice. The second time came minutes after calls
from the robot's first-time setup family (`setInheritInfo`, which decides whether the robot keeps
its previous data, and friends). That is not proven to be the cause, but `send_raw` now refuses
those, and other system and factory calls, outright.

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
| Rooms' names | re-map, edit, restore | `apply_map_setup` (from the automatic snapshot) |
| No-go zones, virtual walls, carpets, furniture | re-map, edit, delete, restore | `restore_map_backup` and `apply_map_setup` (exact positions) |
| Presets and schedules | map loss | `apply_map_setup` (recreated, schedules re-pointed) |
| Room boundaries | re-map | `restore_map_backup`; approximate via `apply_map_setup` |
| Per-room suction/water/passes | - | preset-only on 1.3.3 firmware (`create_preset`) |
