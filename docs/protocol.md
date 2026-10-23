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
`direction_control`). Verified on an RV30 Max Plus firmware 1.3.3.

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
- Error codes seen: `-3016` the map no longer exists (recovery overwrites an existing map, it
  does not recreate a deleted id), `-3002` the robot is mid-task, `-3022`/`-3023` on other
  preconditions.

The recovery logic itself was read from firmware. TP-Link also publishes unencrypted *debug*
builds (`RVSD30_<ver>_Build_<n>.bin.gz`) whose build numbers track the shipping firmware; the
build matching this robot (260206) unpacks to a plain squashfs. Its `robot_control_node`
(`BackupInterface::recoveryMap`) verifies the MD5, unpacks the `.bkmap` into the map's component
files (`.pbstream`, `.area`, forbid/carpet data, room info), then loads it via the Cartographer
interface. None of that is cloud-gated. (The separate `ldrobot.scv` nav-board image is
AES-encrypted, but the recovery path does not live there.)

**Conclusion: a map backup can be restored to the robot entirely locally.**
`tapo_rv30.restore_map_backup` does this, serving a backup that `tapo_rv30.fetch_cloud_map_backups`
has downloaded. Note that deleting a map in the app deletes its cloud backup too, and recovery
overwrites a map the robot still has - so fetch backups ahead of time and keep the map around.

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

`tapo_rv30.save_map_setup` / `apply_map_setup` build on this: snapshot the `area_list` to a file
and write it back, restoring no-go zones, virtual walls, carpets and room names after a remap -
the practical recovery the cloud restore refuses - entirely over the local API. The grid itself
the robot re-maps on its own.

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
