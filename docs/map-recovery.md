# Map backup and recovery

Robot maps are easy to lose - a bad re-map, an accidental delete, a firmware hiccup - and
losing one means redrawing every room, no-go zone and setting by hand. This integration gives
you two independent safety nets, both run from Home Assistant. Neither needs you to be at a PC.

For the protocol detail behind all of this - how backup and restore actually work on the robot,
and why a backup file can't be restored from a local server - see the [protocol notes](protocol.md).

## What a map is made of

A map has two layers:

- **The shape** (the walls and obstacles the robot sensed). The robot builds this with its
  own mapping; nothing, not even the Tapo app, can write it. If it's lost, the robot re-maps
  it by cleaning the floor again.
- **Everything on top**: your **rooms and their names**, **no-go zones**, **virtual walls** and
  **carpets**. These are yours, and this integration can save them and write them back.

So "recovery" is really: let the robot rebuild the shape, then re-apply your layer on top.

## Save and re-apply your map setup (recommended)

This is the recovery that works entirely on your own network, no cloud involved.

- **Save:** `tapo_rv30.save_map_setup` (or the **Save setup** button on the sidebar page's
  **Maintenance** tab) snapshots the current map's no-go zones, virtual walls, carpets and room
  names to `config/tapo_rv30/map_setups/<map_id>.json`. Do this whenever your map is how you
  like it. A good habit is an automation that saves after any map edit.
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
so you keep a copy even if TP-Link's is ever lost. The first run may e-mail you a two-step code;
run it again with `verification_code` set to it, and Home Assistant becomes a trusted device.

A caveat worth knowing: **deleting a map in the app deletes its cloud backup too**, and a cloud
backup can only be restored back to the robot through TP-Link's own cloud, to a map your account
still has. So the cloud backup is a useful archive and loss-detector, but it is not a reliable
way to put a lost map back. For that, use **save/apply map setup** above.

## What's recoverable, at a glance

| Layer | Lost when | Put back by |
| --- | --- | --- |
| Map shape (walls) | re-map, map delete | the robot re-mapping the floor |
| Rooms' names | re-map, edit | `apply_map_setup` |
| No-go zones, virtual walls, carpets | re-map, edit, delete | `apply_map_setup` (exact positions) |
| Room boundaries | re-map | approximate - the robot re-segments |
| Per-room suction/water/passes | - | preset-only on 1.3.3 firmware |
