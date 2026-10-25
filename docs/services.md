# Services and events

Every service lives under `tapo_rv30` (so `tapo_rv30.clean_rooms`). Target the robot by its
vacuum entity, or by a device, area, floor or label that holds it; only Tapo robots in the
target are used, so an area with lights and sensors in it is fine, and a target with no Tapo
robot in it is refused with a clear message. With one vacuum set up the target is optional.

| Service | What it does |
|---|---|
| `clean_rooms` | Clean named rooms (partial match; a name that fits several rooms is refused). Or give `room_ids` (room numbers on the map, as the card sends them) for unnamed rooms or rooms that share a name, with `map_id` (the map they were picked on) so the clean is refused if the robot has since moved to another map. Optional `map` (else the current map; the robot cleans the map it is on, so rooms on another map are refused: switch with `set_map` first). Optional `suction`, `water`, `passes`: the robot has no per-run levels, so these become its default levels for later cleans too. |
| `clean_zone` | Clean rectangles given in map mm, same frame as the `position_mm` attribute. |
| `set_room_settings` | Per-room suction / water / passes stored on the robot. Rejected by RV30 Max Plus firmware 1.3.3 (see [protocol.md](protocol.md)); use `clean_rooms` with levels, or `create_preset` to keep per-room levels. |
| `run_schedule` | Replay a saved schedule's rooms and settings now, by its id (like `S1`). The vacuum has no "run schedule by id" call, so the schedule's suction, water and passes become the robot's default levels and the clean is started; if the start fails, the previous levels are put back. |
| `run_preset` | Start a preset saved in the Tapo app, by name or id. |
| `create_preset` | Make a preset on the robot: `name`, `rooms` (in cleaning order), optional `map`, `suction`, `water`, `passes`, `clean_order`. Levels not given are the robot's current ones. It shows in the Tapo app and runs with `run_preset`. Returns its id. |
| `update_preset` | Change a preset by name or id: new `name`, `rooms` (same map), `suction`, `water`, `passes` or `clean_order`. Anything not given is kept. |
| `delete_preset` | Delete a preset by name or id (`confirm: true`). Schedules that ran it are left pointing at nothing, so change or remove them too. |
| `set_map` | Switch the active map (multi-floor). |
| `add_schedule` | Create a schedule on the robot: time, days, rooms (or `room_ids`) / preset / whole house, levels. Returns the id. Refused when the start time is inside the robot's Do Not Disturb window (the robot would never run it); `ignore_dnd: true` saves it anyway. |
| `set_schedule` | Change a schedule (enable / disable, time, days, rooms or `room_ids`, levels). Same Do Not Disturb check when the time changes or the schedule is enabled. |
| `remove_schedule` | Delete one schedule or all. |
| `set_map_rotation` | Turn a map's display clockwise (`rotation`: 0, 90, 180 or 270; `map`: id or full name, default the current map). Stored on the robot, so the Tapo app shows it the same way. Display only. |
| `rename_map` | Admin only. Rename a saved map on the robot (`map`: its id or full name, `name`: 1 to 32 characters). The robot must be idle; a name that equals, contains or is part of another map's name is refused. Returns the old and new name. |
| `remove_matter_fabric` | Unpair the robot from one Matter ecosystem (fabric index from the Matter sensor). Untested. |
| `get_matter_setup_code` | Admin only, returns a response. The robot's Matter manual pairing code and QR payload. |
| `remote_drive` | The app's remote control, one step per call: `enter` (the robot leaves the dock; the response carries `leaving_dock_ms`), `forward` / `backward` / `left` / `right` (a short nudge; repeat while held), `stop`, `exit`. Refused while a clean is running. |
| `go_to` | Drive to a point (x, y in map mm) on robots with go-to-point; `vacuum.stop` cancels it. |
| `get_clean_records` | Cleaning history and lifetime totals as a service response. |
| `send_raw` | Send any device method with params and get the response back (use with "Return response" in Developer Tools). Refused while the robot is working unless `force: true`; see [protocol.md](protocol.md) for why. Onboarding, reset, firmware, factory and map-deleting methods, and any name that is not a plain method name, are always refused. |
| `save_map_setup` | Snapshot a map's room names, no-go zones, virtual walls, carpets, furniture, presets and schedules to `config/tapo_rv30/map_setups/<robot>` now (this also happens automatically as the map changes). See [map-recovery.md](map-recovery.md). |
| `apply_map_setup` | Put back whatever the map is missing from its saved setup: room names, zones, walls, carpets, furniture, presets and schedules (robot docked and idle, `confirm: true`; `dry_run: true` only reports). `source_map` applies another map's setup, for a re-mapped floor. See [map-recovery.md](map-recovery.md). |
| `fetch_cloud_map_backups` | Download your TP-Link cloud map backups to `config/tapo_rv30/map_backups/<robot>` for safe keeping. See [map-recovery.md](map-recovery.md). |
| `restore_map_backup` | Restore a whole map backup to the robot, locally - Home Assistant serves it on the LAN and the robot fetches and applies it (robot docked and idle, `confirm: true`). Works even when the map is gone from the robot: `map` can be the lost map's name or id, and the current map carries the restore (its room names and furniture are put back afterwards). `new_name` restores it as a new map with that name instead of over it. See [map-recovery.md](map-recovery.md). |
| `copy_map` | Copy a map (`map`, default the current one) to a new map called `name`: same grid, rooms, room names, no-go zones and furniture; the original is left as it is. Backs the map up to the TP-Link cloud, downloads it and restores it as a new map, so it needs the cloud login; docked and idle; the robot holds at most 3 maps. Admin only. See [map-recovery.md](map-recovery.md#restore-as-a-new-map-or-copy-a-map). |
| `delete_map` | Delete a map from the robot (`map`: full name or id, `confirm: true`), as the Tapo app does; its presets and schedules go with it. Never the current map (switch first) and never the last saved map; docked and idle. Admin only. The response lists the backups Home Assistant still holds of it. |

Bad input (unknown room, map, option) raises an error with the available
names in it, so it shows in the UI and in automation traces.

## Events

| Event | When | Data |
|---|---|---|
| `tapo_rv30_clean_started` | a clean begins | `device`, `status_code`, `current_room` |
| `tapo_rv30_clean_finished` | a running or paused clean ends (stopped, docking) | `device`, `status_code`, `record` (area, minutes, bin emptied, preset name) when the robot logged one |
| `tapo_rv30_planner` | the planner starts a run, or in preview would have | `device`, `kind` (`start` or `preview`), `rooms`, `by` |
| `tapo_rv30_error` | the robot reports a new error | `device`, `code`, `error`, `current_room` |
| `tapo_rv30_prompt` | the robot raises a notice (dust bag full, area unreachable, cleaning finished, water tank empty and others), once each time | `device`, `code`, `prompt` (for example `dust_bag_full`), `description`, `prompt_id`, `current_room`. Codes in [protocol.md](protocol.md#status-prompts) |

## Xiaomi Vacuum Map Card calibration

The map camera's `calibration_points` attribute holds three ready-made points for the
[Xiaomi Vacuum Map Card](https://github.com/PiotrMachowski/lovelace-xiaomi-vacuum-map-card),
in the millimetre frame that `tapo_rv30.clean_zone` expects. Paste them into the card's
`calibration_source.calibration_points` and point zone cleaning at `tapo_rv30.clean_zone`.
The `map_geometry` and `room_geometry` attributes give the full mm to pixel transform and
each room's pixel bounds for custom cards.
