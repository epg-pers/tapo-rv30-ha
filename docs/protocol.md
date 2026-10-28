# Protocol notes

What the robot answers over its local TPAP (SPAKE2+) transport, learned from live traffic,
the forks, and the Tapo Android app's code. `tapo_rv30.send_raw` lets you try any method
against your own robot, docked.

## Login: device attestation on tls 0

A robot that answers discovery with `tls: 0` and `dac: 1` (seen on an RV30 Max Plus Gen2,
firmware 1.3.5) has no TLS certificate to check, so it proves its identity in the handshake
instead. The client sends a random `dac_nonce` with `pake_share`; the reply carries `dac_ca`
(the device's attestation certificate), `dac_ica` (the intermediate) and `dac_proof`, an
ECDSA SHA-256 signature over the SPAKE2+ SharedKey followed by the decoded nonce.

`dac_ca` and `dac_ica` are base64 of PEM text: the Tapo app base64-decodes them and reads the
result with a PEM reader. The chain must lead to one of the two TP-Link device roots the app
pins (TP-LINK SYSTEMS DEVICE ROOT CA, TP-LINK GLOBAL DEVICE ROOT CA). The app itself only does
this for robots offering the default passcode type (`pake` containing 0); this integration
does it whenever a tls 0 robot offers attestation.

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
`direction_control`). Verified on an RV30 Max Plus firmware 1.3.3.

- `directionControl {"direction": 0, "control": true}` enters remote control; the answer
  carries `away_sta_ms`, how long the robot takes to leave the dock (the app counts it
  down and assumes 4000 ms when absent). `{"direction": 4, "control": false}` leaves it.
- `directionControl {"direction": n}` drives: 0 forward, 1 backward, 2 left, 3 right,
  4 stop. The app sends the held direction, waits for the answer, pauses 300 ms and sends
  it again while the finger stays down; lifting sends 4. Status is 3 ("Remote Control")
  meanwhile.
- `getSweepWalk` / `setSweepWalk {"sweepWalk": bool}` is "clean while moving" (the Sweep
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
  path (`pos_array`, `pos_len`). This is what the Last Clean Map image renders, through the
  same clean-up and colours as the live map, as the Tapo app does.

## Maps: backup, restore and setup

The map has two layers with completely different write paths.

**The grid** - the occupancy pixels, i.e. the walls and obstacles the robot sensed - is built
by SLAM and is not writable by anything, the app included. `getMapData {"map_id"}` returns it
as an LZ4 block (`map_data`, `pix_len`, `pix_lz4len`, `width`, `height`, `resolution`) with
`origin_coor`/`real_origin_coor`, `charge_coor`, `vac_coor` and `map_hash`.

**Everything on top** - rooms and their names, no-go zones, virtual walls and carpets - is the
`area_list`, and it *is* writable (see `setAreaInfo` below).

### Cloud backup and restore (mapBackup / mapRecovery)

"Back up map" in the app is `mapBackup {"map_id": <int>}`: the robot uploads its own map to
TP-Link storage (an AWS S3 bucket, `prd-iot-as-euw1.s3.eu-west-1.amazonaws.com/<thing>/robotVacMap/<map_id>`).
`getMapBRProcess {"map_id"}` reports `{type, process, status}` - `type` 1 backup / 2 restore /
0 idle, `status` 2 running / 3 success / 13 failed, `process` percent. The account's backup
list is a signed `GET {thingUrl}/v1/things/{thingName}/map/detail` returning
`[{mapId, mapUrl, mapMd5, snapshotUrl, timestamp}]`. The backup file is the robot's own binary
format: a short header (`"MZ"` + 16 bytes + `0xAA55`), a gzip tar of the raw map files
(`map.gridmap`, `map.segmentmap`, `area_info.json`, `area_user.json`, `charger_pose.json`,
`navmap_bound.json`, `path_record`, `path_map`), then a JSON tail. The 16-byte header is a
keyed digest, not a plain hash; the rest is plaintext.

Restore is `mapRecovery {"map_id", "map_md5", "url"}`: the robot downloads the file at `url`,
checks its MD5, unpacks it and applies it. **It works from a local URL - no cloud round-trip.**
The integration serves the backup from Home Assistant and the robot fetches and applies it.
Verified end to end on an RV30 Max Plus (fw 1.3.3): a change to a live map was restored back to
the backed-up state, `getMapBRProcess` reaching `process: 100`, `status: 3`, robot docked.

The one real constraint is the robot's HTTP client, and it caused a long detour worth recording:

- The robot's downloader needs a plain response with a correct `Content-Length` (which aiohttp's
  `FileResponse` sends). Served that way - Home Assistant's **direct LAN address** - the download
  completes and the map applies.
- Served through a **reverse proxy** in front of Home Assistant (the external hostname here was
  fronted by OpenResty), the proxy re-chunks the body. The robot's client reads the bytes but
  never sees the end marker it understands, so `getMapBRProcess` climbs to ~92-99% and then flips
  to `status: 13`. This looked like an apply-step rejection but is an unfinished download; the
  direct-LAN URL fixes it. (A TP-Link S3 presigned URL also works, for the same reason - clean
  `Content-Length`.)
- Error codes seen: `-3016` the `map_id` sent is not on the robot (the carrier must exist; the
  backup itself may be of a deleted map, see below), `-3002` the robot is mid-task,
  `-3022`/`-3023` on other preconditions.

The recovery logic itself was read from firmware. TP-Link also publishes unencrypted *debug*
builds (`RVSD30_<ver>_Build_<n>.bin.gz`) whose build numbers track the shipping firmware; the
build matching this robot (260206) unpacks to a plain squashfs. Its `robot_control_node`
(`BackupInterface::recoveryMap`) verifies the MD5, unpacks the `.bkmap` into the map's component
files (`.pbstream`, `.area`, forbid/carpet data, room info), then loads it via the Cartographer
interface. None of that is cloud-gated. (The separate `ldrobot.scv` nav-board image is
AES-encrypted, but the recovery path does not live there.)

**Conclusion: a map backup can be restored to the robot entirely locally.**
`tapo_rv30.restore_map_backup` does this, serving a backup that `tapo_rv30.fetch_cloud_map_backups`
has downloaded. Deleting a map in the app deletes its cloud backup too, so fetch backups ahead
of time.

**Restoring a map that no longer exists.** `mapRecovery` only accepts a `map_id` the robot
currently has (otherwise -3016, the same "no such map" code `getMapData` uses). But the backup
lands under the map id it was taken from, not the one passed: with the original map gone it is
recreated under its old id as the current map, unnamed and with `is_saved: false` in
`getMapInfo`, and saving it in the app keeps that id. So after a total loss, any map (even a
throwaway quick mapping run) can carry the restore. The grid and room segmentation come back;
room names, some no-go zones and the furniture did not, and presets
(`getCustomizationRulesInfo`) and schedules had gone with the map, which is why the integration
keeps its own map setup snapshots (`addCustomizationRule` with the same body
`getCustomizationRuleData` returns, minus `rule_id`, recreates a preset; the robot assigns a new
id).

**Where the backup's room names and furniture go.** The `.bkmap` ends in a JSON tail
(`area_list` with room names, colours and per-room flags, plus `furniture_list`). The robot
writes that tail onto the map that **carried** the restore (the `map_id` passed), not onto the
map it restored. Over its own map that is the same map; onto a carrier it blanks the carrier's
room names and colours and swaps its furniture for the backup's, while the restored map gets
none. The integration snapshots the carrier's rooms and furniture before `mapRecovery` and writes
them back afterwards, and writes the tail onto the restored map. `setAreaInfo` and
`setFurnitureInfo` honour the `map_id` they are given, current map or not.

**Map lock.** `getMapInfo` reports `map_locked` per map (0 unlocked, 1 locked, 2 locked by the
robot itself) on robots that list the `map_lock` component. The app locks and unlocks with
`setMapInfo` and one `map_list` entry holding only `map_id` and `map_locked` (true / false).
Checked on an RV30 Max Plus (1.3.3): the lock reads back at once, and `setAreaInfo` /
`setFurnitureInfo` are still accepted on a locked map. When the robot finds changes on a locked
map the app offers the update (`getOldMapData`, `setUpdateMapDataInfo` with `applied` and
`map_locked`); the integration does not use those yet.

**The `.bkmap` layout and copies.** A 25-byte fixed prefix (`MZ`, 16 constant bytes, `AA 55`,
uint32 version 2, a length byte of 32), the 32-character hex MD5 of the gzip member, `01` and the
member's length (uint32 big-endian), the gzip'd tar, then `03`, a uint32 big-endian length and the
JSON tail. The map id is the last 8 bytes of `map.gridmap` (int64 little-endian) and `"mapId"` in
`area_info.json` and `area_user.json`. Changing it there (same width, so no tar header changes),
re-gzipping and rewriting the MD5 and length gives a backup the robot restores as a **new** map
beside the original. `saveMap` with only `new_map_name` (base64) then saves the current unsaved
map under that name, keeping its id; its `replace_map_id` would save it over another map and is
never sent. `mapBackup` (`map_id`) writes a fresh backup to the cloud; `getMapBRProcess` reports
it (`type` 1 backup, 2 recovery; `status` 3 done, 13 failed). The firmware keeps at most 3 maps.

### Writing the editable layers (setAreaInfo)

`setAreaInfo` is the method the app uses for
every map edit, and it needs no cloud:

```json
{"map_id": <int>, "type_list": ["forbid"], "area_list": [ { "type": "forbid", "vertexs": [[x,y], ...] } ]}
```

`type_list` names which area types the call replaces; the robot swaps all areas of those types
for `area_list` (an empty list clears them). Types: `room`, `forbid` (no-go zone),
`virtual_wall`, `carpet_rectangle`, `carpet_round`. Each entry (`RobotAreaData`) carries `type`,
`id`, `name`, `vertexs` and the finish fields (`color`, `floor_texture`, `floor_material`,
`carpet_strategy`). **`vertexs` are world-coordinate (mm) polygons**, so they re-apply onto any
grid whatever its shape - which is why they survive a remap. Verified on an RV30 Max Plus:
writing and clearing `forbid` and `virtual_wall` round-trips exactly (the robot renumbers ids
but keeps the polygons). Per-room clean settings (suction/water/passes) are not here; those go
through `setCleanAttr`, preset-only on 1.3.3 (see Room cleaning).

**Cleaning direction per room.** A room's `floor_texture` is its cleaning direction (the app's
map management "Cleaning Direction", shown when the component list has `clean_angle` at
version 1 or later; an RV30 Max Plus reports 1): `-1` the robot's own pattern (Default), `0` or
`90` the two directions in the robot's map frame. One value per room for vacuuming and mopping
together; presets send `null` for it and there is no global one (the separate "clean along the
wood grain" switch is **Clean Along Floor**). The app labels them as the map is displayed:
at `rotate_angle` 0 or 180, Horizontal is `0` and Vertical `90`; at 90 or 270 they swap.
Home Assistant does the same with the map's rotation. The app writes it with `setAreaInfo`,
`type_list` `["room"]` and every room (`name`, `color`, `carpet_strategy`, `floor_texture`,
`floor_material`, `label`; no `vertexs`), changing only the target room's `floor_texture`.
Since `["room"]` replaces all rooms, the integration always builds that list from a fresh
`getMapData` read, as its other room writes do; the service reads the map back to confirm.

`tapo_rv30.save_map_setup` / `apply_map_setup` build on this: snapshot the `area_list` to a file
and write it back, restoring no-go zones, virtual walls, carpets and room names after a remap -
the practical recovery the cloud restore refuses - entirely over the local API. The grid itself
the robot re-maps on its own.

## Presets (customisation rules)

A preset is a "customisation rule" on the robot, stored per map. Verified live on 1.3.3 by
creating, editing and deleting a throwaway preset.

- List: `getCustomizationRulesInfo` returns `rule_list` of `{rule_id, rule_name (base64), mode,
  map_id, invalid}`.
- Read one: `getCustomizationRuleData {"map_id", "rule_id"}` returns the full body below.
- Create: `addCustomizationRule` with
  ```json
  {"rule_name": "<base64>", "mode": "room", "map_id": <int>, "clean_order": true,
   "area_list": [{"id": 2, "type": "room", "suction": 2, "cistern": 1, "clean_number": 1,
                  "carpet_strategy": 1}]}
  ```
  `area_list` is in cleaning order; `carpet_strategy` is copied from the map's room and left out
  when the room has none. The robot picks the next free `rule_id`.
- Edit: the same call with `rule_id` added. The app uses one call for both.
- Delete: `delCustomizationRule {"map_id", "rule_id"}`.
- Run: `setSwitchClean` with `clean_mode` 5 and `custom_rule_id`. Schedules that run a preset
  carry the same `custom_rule_id` in their `clean_attr`, so deleting a preset leaves those
  schedules pointing at nothing.

This is the only place per-room levels stick on firmware that rejects `setCleanAttr` type
`custom`. `create_preset`, `update_preset` and `delete_preset` wrap these calls.

## Status prompts

`getVacStatus` carries `prompt` (a list of codes) and `promptCode_id` (a matching list of ids,
new for each time a notice is raised). They are the notices the app shows and the robot speaks.
Names follow the app's `RobotPromptType`; 32 and 36 come from the firmware's event table.

| Code | Notice | Code | Notice |
|---|---|---|---|
| 1, 2 | battery too low to start | 17 | firmware update succeeded |
| 3 | mop installed | 18 | recharged, returning to where it stopped |
| 4 | mop removed | 19 | charging stopped |
| 5 | emptying the dustbin | 20 | dustbin emptied |
| 6 | cleaning finished | 21 | some of the area is unreachable |
| 7 | low battery, returning to recharge | 22 | could not relocate, building a new map |
| 8 | updating firmware, cannot clean | 23 | started inside a no-go zone |
| 9 | charged, resuming the clean | 30 | stuck for too long |
| 10 | charging state unknown | 31 | paused to recharge |
| 11 | dust bag full | 32 | clean the charging contacts |
| 12 | dust bag missing | 33 | water tank empty |
| 13 | dust duct blocked | 36 | dock busy |
| 14 | emptying too often | | |
| 15 | battery too low, shutting down | | |
| 16 | firmware update failed | | |

The integration fires `tapo_rv30_prompt` once per new `promptCode_id` (or per new code on
firmware that sends no ids).

## Other calls verified on the RV30 Max Plus

`gotoPoint {"switch": true, "point": [x, y]}` (status becomes 11, Going To Point; `switch:
false` cancels), `getDustCollectionInfo` / `setDustCollectionInfo` (`dust_collection_mode`
0 smart, 1 light, 2 balanced, 3 max), `getAutoUpdateInfo` / `setAutoUpdateInfo`
(`enable`, `time`, `random_range`), `getCarpetClean` / `setCarpetClean`
(`carpet_clean_prefer` boost / normal, the same setting as `setCarpetAutoBoost`),
`getCurrentVoiceLanguage` (an md5 of the voice pack; changing it needs a cloud URL),
`getMatterSetupInfo`, `getCommissionedStatus`, `startCommission` (see [matter.md](matter.md)).

Omni dock actions: `getBackWashMode` / `setWashMopSwitch`, `getDryMopMode` / `setDryMopSwitch`,
`getCutHairMode` / `setCutHairSwitch`. The app sends `{"switch": true}` to all three setters
(`BaseStationSwitchCommandParams` and `RobotCutHairStatus` both serialise their one field as
`switch`); the per-action keys some forks use are not what the app sends. Untested here (no
Omni dock on the RV30 Max Plus).

Unknown on this firmware (-1002): voice pack listing, lifetime statistics beyond
`getCleanRecords` totals, `getCleanOrder`, `getCleanTaskGroupList`.

## Full endpoint map

The robot's local API dispatcher (the `VAC` binary in the firmware) carries a table of method
names. The list below is from the unencrypted RVSD30 debug build cross-checked against the live
RV30 Max Plus on 1.3.3: each method was called read-only where safe, and marked by what the
robot actually answered. `-1002` means the robot does not know the method; `-1001` means it
knows it but rejected the call (wrong parameters or state).

**Already used by the integration:** `getVacStatus`, `getBatteryInfo`, `getCleanInfo`
(carries `clean_percent`, the live progress), `getCleanStatus`, `getCleanAttr` / `setCleanAttr`,
`getMapInfo` / `setMapInfo`, `getMapData`, `getPathData`, `getAreaInfo` / `setAreaInfo`,
`getFurnitureInfo` / `setFurnitureInfo`, `getCleanRecords` / `getCleanRecordExtraInfo`,
`getScheduleRules` / `addScheduleRule` / `editScheduleRule` / `removeScheduleRules`,
`getCustomizationRulesInfo` / `getCustomizationRuleData` / `addCustomizationRule` /
`delCustomizationRule`, `getConsumablesInfo` /
`resetConsumablesTime`, `getVolume` / `setVolume`, `getDoNotDisturb` / `setDoNotDisturb`,
`getDustCollectionInfo` / `setDustCollectionInfo` / `setSwitchDustCollection`, `getMopState`,
`getChildLockInfo` / `setChildLockInfo`, `getCarpetAutoBoost` / `setCarpetAutoBoost`,
`getSweepWalk` / `setSweepWalk`, `getComponentList`, `getAutoUpdateInfo` / `setAutoUpdateInfo`,
`setRobotPause`, `setSwitchClean` / `setSwitchCharge`, `mapBackup` / `mapRecovery` /
`getMapBRProcess`, `deleteMap`, `playSelectAudio`, plus the 1.3.x switch family
(`get/setAiAvoidSwitch`, `get/setExtendedMoppingSwitch`, `get/setAutomaticRemoppingSwitch`,
`get/setCleanAlongFloorSwitch`, `get/setPetAreaDeepSwitch`, `get/setDryMopMode`,
`get/setCutHairMode`, `get/setBackWashMode`) and the Matter calls.

**Confirmed on 1.3.3 but newly wired up / available to wire up:**

- `getAutoChangeMap` / `setAutoChangeMap` (`{auto_change_map: bool}`) - whether the robot picks
  the matching saved map automatically when it relocates on a different floor. **Now exposed as
  the "Auto-change Map" switch.**
- `getRobotPauseTime` (`{pause_min}`) - how long the robot waits, paused, before it gives up and
  returns to the dock. Read-only companion to `setRobotPause`; could be a number entity.
- `getAreaUnit` / `setAreaUnit` (`{area_unit}` 0 = m2) - unit for reported clean areas.
- `getDeviceTime` (`{time_diff, timestamp, region}`), `getDstTime` / `setDstTime` / `startDST` -
  clock, timezone and daylight-saving. `getInheritInfo` (`{inherit_status}`) reads but
  `setInheritInfo` rejected the obvious shape (-1001); the write form is still unknown.
- `getWifiBasic` (`{ssid, key_type, rssi}`), `getWirelessConnectedStatus`, `getWirelessScanInfo` -
  network info; `rssi` is already surfaced via `getDeviceInfo`.
- Voice: `getCurrentVoiceLanguage`, `getVoiceDownloadState`, `setVoiceLanguage` - voice-pack
  management (changing the pack needs a cloud download URL).

**Actions present in the dispatcher, not yet wired (each drives the robot, so they need
supervised live testing before shipping):**

- `switchFastMapping` - run a quick mapping sweep to build a map without cleaning.
- `switchExploringNewArea` - send the robot to explore and extend the current map.
- `runCleanTask` - the unified clean entry point. The ROS service behind it
  (`BridgeRoomCleanTask` / `BridgeTotalCleanTask` / `BridgeSelectCleanTask`) takes per-area
  `fan_level`, `water_level`, `clean_number`, `clean_order`, `clean_interval_type`, `clean_type`,
  `start_type` and `clean_mode`; the integration currently drives the same outcomes through
  `setCleanAttr` + `setSwitchClean`.
- `saveMap` / `startUpdateMapData` - map build lifecycle, used around mapping runs.
- `deleteCleanRecord` - remove a single run from history.

**Not supported on this firmware (-1002):** `getLidarFreqPercent` / `setLidarEnabled`,
`getSupportVoiceLanguage`, `getNextEvent` (-1001; present but rejected bare), `getCleanOrder`,
`getCleanTaskGroupList`.

## Firmware details

Learned from the RVSD30 firmware build, the Tapo app and live calls on 1.3.3.

**Clean start fields** (`setSwitchClean`, and `runCleanTask` which takes the same keys):

- `clean_mode`: 0 whole house, 1 whole house with per-room settings, 2 spot, 3 rooms, 4 zones,
  5 preset.
- `start_type`: who started it. 0 the robot's button, 1 the app (what the integration sends),
  4 a schedule; other values exist. Clean records report the same field.
- `force_clean`: `true` starts the new job over one that is already running instead of being
  refused.
- `clean_type` (per job or per room, also in clean records): 0 vacuum and mop, 1 mop only,
  2 vacuum only, 3 vacuum then mop, 4 AI.
- Cleaning density, logged by the firmware as `clean_density`: 1 daily, 2 fast (skips the edge
  pass), 3 meticulous.
- `setCleanAttr` `type`: `global` (the default levels), `pose` (spot and go-to levels),
  `running` (the job in progress), `custom` (per-room, rejected on 1.3.3).

**Other read calls:** `getCleanStatus` returns `{clean_status, is_working, is_mapping,
is_relocating}`. `getCleanAttr {"type": "pose"}` works. `getCarpetClean` returns
`{carpet_clean_prefer}`. `getConsumablesInfo` includes `rag_time` (mop cloth minutes), reset
with `resetConsumablesTime {"reset_list": ["rag"]}` like the other parts.

**`playSelectAudio`** only accepts `"seek_me"` (the "find my robot" call) and `"test"`.

**Component gating.** `getComponentList` returns `{id, ver_code}` pairs and the app hides
features by them. On an RV30 Max Plus (1.3.3): `clean` 3, `map` 2, `auto_change_map` 2,
`map_lock` 1, `continue_breakpoint_sweep` 1, `charge_pose_clean` 1. A missing component means
the app does not offer the feature, even when the method answers.

**Unknown on 1.3.3 (-1002), though other firmware has them:** `getContinueThreshold`,
`getCliffDetectMode`, `getCarpetDefVal`, `getCarpetThreshold`, `getCarpetDeepSwitch`,
`getPetAreaDeepInfo`, `getMopPrefer`, `getValleyChargingTime`, `getOfflineMapSwitch`,
`getHiddenArea`.

**Status, error and level tables** in the firmware (status codes 0 to 19, error codes, fan,
water and auto-empty values) match the tables the integration already uses.

**Never send these.** The dispatcher holds 162 methods, including factory and debug ones
(`exec_atcmd`, `erase_flash`) and the onboarding, reset, reboot, firmware and Wi-Fi families.
`send_raw` refuses them, even with `force`. `setInheritInfo` and the quick-setup calls are on
that list: a batch of setup and inherit calls came minutes before one robot lost every map.

**No camera/video endpoints exist** - the RV30 navigates by LiDAR and structured light, so there
is no live-view or snapshot stream to expose (the dispatcher has nothing of the sort).
