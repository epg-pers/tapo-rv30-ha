# Protocol notes

What the robot answers over its local TPAP (SPAKE2+) transport, learned from live traffic,
the forks, and the Tapo Android app's code. `tapo_rv30.send_raw` lets you try any method
against your own robot, docked.

## Room cleaning

The `setSwitchClean` payload for selective room cleaning was reverse-engineered here
from live device traffic and later contributed to
[python-kasa](https://github.com/python-kasa/python-kasa)
([#1660](https://github.com/python-kasa/python-kasa/pull/1660)).

The payload is:

```json
{
  "clean_mode": 3,
  "clean_on": true,
  "clean_order": true,
  "force_clean": false,
  "map_id": <int>,
  "room_list": [<room_id>, ...],
  "start_type": 1
}
```

`clean_mode` values: `0` whole house, `1` whole house with per-room settings, `2` spot,
`3` selected rooms (`room_list`), `4` zones (`area_list` of rectangles in mm, which is also
what the app uses for spot clean), `5` a saved preset (`custom_rule_id`, listed by
`getCustomizationRulesInfo`). `room_list` holds the room ids, which are the pixel values
in the LZ4 map. `tapo_rv30.send_raw` lets you try any method against your own robot.

**Per-room settings.** The app writes them with `setCleanAttr {"type": "custom", "area_list":
[...]}` (`RobotRepoClean.X2` in the app). RV30 Max Plus firmware 1.3.3 answers -1001 to every
shape of that call, and -1008 to `getCleanAttr {"type": "custom"}`, so on that firmware the
only per-room settings that stick are the ones inside a preset. `set_room_settings` stays for
firmware that accepts it and explains itself when it is refused; the card's long-press sheet
starts a clean of that room with the chosen levels instead.

**Do not probe a robot while it is working.** On 2026-10-21 an RV30 Max Plus was sent a
batch of read-only setup and backup queries lifted from the app (`getQsComponentList`,
`getInheritInfo`, `getCommissionedStatus`, `getMatterSetupInfo`, `getMapBRProcess`,
`getOflMapSwitch`) about 38 minutes into a scheduled clean. Within seconds it aborted the
run with an error, its saved maps and clean history were gone, and the map backups in the
Tapo app with them. None of those methods is documented as destructive and the cause is
not proven, but the timing is hard to ignore. `send_raw` therefore refuses anything but the
methods the integration itself uses while the robot is cleaning, returning or paused,
unless you pass `force: true`. Probe docked, and leave setup, inherit, commissioning and
map backup / recovery methods alone unless you can afford to remap.

Furniture placed in the app comes back from `getFurnitureInfo {"map_id": <int>}` (and inside
the map blob) as `{id, type, angle, vertexs}`; the map camera lists it in
`map_geometry.furniture` with the type name, and the map draws each item with its own glyph.
Type codes (from the app's `RobotFurnitureType`): 1 single bed, 2 double bed, 101 single
sofa, 102 double sofa, 103 sectional sofa, 201 table and chairs, 202 square table, 203 end
table, 301 TV cabinet, 302 wardrobe, 303 bedside table, 401 refrigerator, 402 front-load
washer, 403 vertical air conditioner, 503 green plants, 601 toilet, 701 pet house, 702 cat
litter box, 703 pet bowl. The glyphs are the integration's own drawings, not the app's icons.

## Remote control

From the app's `RobotRemoteControlViewModel` and its control view (component
`direction_control`). Not yet verified on a robot.

- `directionControl {"direction": 0, "control": true}` enters remote control; the answer
  carries `away_sta_ms`, how long the robot takes to leave the dock (the app counts it
  down and assumes 4000 ms when absent). `{"direction": 4, "control": false}` leaves it.
- `directionControl {"direction": n}` drives: 0 forward, 1 backward, 2 left, 3 right,
  4 stop. The app sends the held direction, waits for the answer, pauses 300 ms and sends
  it again while the finger stays down; lifting sends 4. Status is 3 ("Remote Control")
  meanwhile.
- `getSweepWalk` / `setSweepWalk {"sweep_walk": bool}` is "clean while moving" (the Sweep
  Walk switch). The app's "spot clean here" is an ordinary spot clean (clean_mode 2).

## Schedules

The app posts the schedule rule as-is. Verified on an RV30 Max Plus:

- `addScheduleRule` with `{"enable", "mode": "repeat", "week_day", "s_min", "start_remind",
  "alarm_min", "clean_attr": {...}}` answers `{"id": "S1"}`.
- `editScheduleRule` needs the whole rule including `id` (a partial body is -1008).
- `removeScheduleRules {"remove_all": bool, "rule_list": ["S1"]}`.
- `week_day` is a bitmask, Sun=1 ... Sat=64. `s_min` is minutes after midnight in the robot's
  own region; the app only shifts it when the phone's zone differs from the robot's.
- `clean_attr` carries `clean_mode` (0 whole house, 3 rooms with `room_list` and `map_id`,
  5 preset with `custom_rule_id`), `suction`, `cistern`, `clean_number`, `clean_order`.
- A one-off rule (`mode: "once"` with `year`, `month`, `day`) was stored by the robot on a
  different date than asked, so the integration refuses to create them.
- A schedule whose `s_min` falls inside the Do Not Disturb window (`getDoNotDisturb`,
  `s_min` / `e_min`, may cross midnight) is accepted and stored but never fires: with DND
  covering the time, a daily rule three minutes ahead left the robot docked and logged
  nothing. The app warns about this; the integration flags such schedules
  (`blocked_by_dnd` in the schedules sensor) and refuses to create or enable one unless
  asked with `ignore_dnd`.

## Path and records

- `getPathData {"path_id": N, "start_pos": 0}` returns the run's path as an LZ4 block:
  8-byte header, then big-endian int16 (x, y) pairs in mm.
- `getCleanRecordExtraInfo {"record_index": N}` returns a finished run with its own map grid
  (cells the robot cleaned are 255, skipped rooms keep their ids), overlays, furniture and the
  path (`pos_array`, `pos_len`). This is what the Last Clean Map image renders.

## Other calls verified on the RV30 Max Plus

`gotoPoint {"switch": true, "point": [x, y]}` (status becomes 11, Going To Point; `switch:
false` cancels), `getDustCollectionInfo` / `setDustCollectionInfo` (`dust_collection_mode`
0 smart, 1 light, 2 balanced, 3 max), `getAutoUpdateInfo` / `setAutoUpdateInfo`
(`enable`, `time`, `random_range`), `getCarpetClean` / `setCarpetClean`
(`carpet_clean_prefer` boost / normal, the same setting as `setCarpetAutoBoost`),
`getCurrentVoiceLanguage` (an md5 of the voice pack; changing it needs a cloud URL),
`getMatterSetupInfo`, `getCommissionedStatus`, `startCommission` (see [matter.md](matter.md)).

Omni dock actions from the cavefire and jan-tdy forks, untested here: `getBackWashMode` /
`setWashMopSwitch`, `getDryMopMode` / `setDryMopSwitch`, `getCutHairMode` / `setCutHairSwitch`.

Unknown on this firmware (-1002): voice pack listing, lifetime statistics beyond
`getCleanRecords` totals, `getCleanOrder`, `getCleanTaskGroupList`.
