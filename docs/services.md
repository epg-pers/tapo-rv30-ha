# Services and events

Every service lives under `tapo_rv30` (so `tapo_rv30.clean_rooms`). Target the robot by its
vacuum entity, or by a device, area, floor or label that holds it; only Tapo robots in the
target are used, so an area with lights and sensors in it is fine, and a target with no Tapo
robot in it is refused with a clear message. With one vacuum set up the target is optional.

| Service | What it does |
|---|---|
| `clean_rooms` | Clean named rooms (partial match). Optional `map`, `suction`, `water`, `passes` for this run. |
| `clean_zone` | Clean rectangles given in map mm, same frame as the `position_mm` attribute. |
| `set_room_settings` | Per-room suction / water / passes stored on the robot. Rejected by RV30 Max Plus firmware 1.3.3 (see [protocol.md](protocol.md)); use `clean_rooms` with levels or a preset there. |
| `run_schedule` | Replay a saved schedule's rooms and settings now. The vacuum has no "run schedule by id" call, so the settings are re-sent and the clean started. |
| `run_preset` | Start a preset saved in the Tapo app, by name or id. |
| `set_map` | Switch the active map (multi-floor). |
| `add_schedule` | Create a schedule on the robot: time, days, rooms / preset / whole house, levels. Returns the id. Refused when the start time is inside the robot's Do Not Disturb window (the robot would never run it); `ignore_dnd: true` saves it anyway. |
| `set_schedule` | Change a schedule (enable / disable, time, days, rooms, levels). Same Do Not Disturb check when the time changes or the schedule is enabled. |
| `remove_schedule` | Delete one schedule or all. |
| `remove_matter_fabric` | Unpair the robot from one Matter ecosystem (fabric index from the Matter sensor). Untested. |
| `remote_drive` | The app's remote control, one step per call: `enter` (the robot leaves the dock; the response carries `leaving_dock_ms`), `forward` / `backward` / `left` / `right` (a short nudge; repeat while held), `stop`, `exit`. Refused while a clean is running. |
| `go_to` | Drive to a point (x, y in map mm) on robots with go-to-point; `vacuum.stop` cancels it. |
| `get_clean_records` | Cleaning history and lifetime totals as a service response. |
| `send_raw` | Send any device method with params and get the response back (use with "Return response" in Developer Tools). Refused while the robot is working unless `force: true`; see [protocol.md](protocol.md) for why. |

Bad input (unknown room, map, option) raises an error with the available
names in it, so it shows in the UI and in automation traces.

## Events

| Event | When | Data |
|---|---|---|
| `tapo_rv30_clean_started` | a clean begins | `device`, `status_code`, `current_room` |
| `tapo_rv30_clean_finished` | a running or paused clean ends (stopped, docking) | `device`, `status_code`, `record` (area, minutes, bin emptied, preset name) when the robot logged one |
| `tapo_rv30_error` | the robot reports a new error | `device`, `code`, `error`, `current_room` |

## Xiaomi Vacuum Map Card calibration

The map camera's `calibration_points` attribute holds three ready-made points for the
[Xiaomi Vacuum Map Card](https://github.com/PiotrMachowski/lovelace-xiaomi-vacuum-map-card),
in the millimetre frame that `tapo_rv30.clean_zone` expects. Paste them into the card's
`calibration_source.calibration_points` and point zone cleaning at `tapo_rv30.clean_zone`.
The `map_geometry` and `room_geometry` attributes give the full mm to pixel transform and
each room's pixel bounds for custom cards.
