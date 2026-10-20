# Changelog

## v0.8.1

- Integration icon. Home Assistant 2026.3+ serves it straight from `custom_components/tapo_rv30/brand/`, so it shows on the Integrations page and in HACS without a `home-assistant/brands` submission.

## v0.8.0

### New

- **Presets.** The cleaning presets you save in the Tapo app ("customisation rules") are read from the robot: one button per preset, a `tapo_rv30.run_preset` service (by name or id), and the preset's rooms and per-room settings as attributes. They start natively (`clean_mode 5`), so the robot behaves exactly as if the app had started them. Verified on an RV30 Max Plus. Found in @cavefire's fork.
- **Capability discovery.** The robot's component list (`getComponentList`) and a one-off probe of its optional settings decide which entities exist, so RV20, RV30 and RV50 share one codebase. New switches appear automatically when the model answers: AI obstacle avoidance, automatic re-mopping, clean along floor, extended mopping, pet area deep clean, sweep walk. Components are in the diagnostics download.
- `tapo_rv30.set_map` switches the active map for multi-floor homes; `run_preset` switches automatically when needed.
- **Charging** binary sensor (@danieyal).
- Ready-made `calibration_points` on the map camera for the Xiaomi Vacuum Map Card, in the millimetre frame `clean_zone` uses (idea from @ckarlof's guide).

### Changed

- **TPAP transport hardening**, ported from @danieyal's fork: P-384 and P-521 SPAKE2+ suites, the factory default passcode for robots that advertise it, TLS modes 0/1/2 (plain, self-signed, verified against the TP-Link root CA), device attestation (DAC) checks, and session-lost versus wrong-credentials error classification so a lapsed session re-handshakes while a bad password raises reauth.
- **Security**, following @Charles226's audit: the session cache is JSON (never pickle), written 0600 under Home Assistant's `.storage/tapo_rv30/`; the self-signed TLS warning is silenced per request instead of process-wide; map data from the robot is validated (size, pixel count, room count) and the LZ4 decoder is bounds-checked, so a malformed map is skipped rather than stalling Home Assistant.
- Errors from buttons, switches, numbers, times and vacuum commands show the device's message in the UI instead of "Unexpected exception" (@jan-tdy).

## v0.7.0

### New

- **Map image** now draws no-go zones (red), virtual walls, carpets, saved clean zones (blue) and furniture outlines, and the robot marker moves on every poll instead of every 5 minutes. The map camera exposes `room_geometry` (each room's pixel bbox and centre) and `map_geometry` (mm to pixel transform, dock position) so a custom card can map clicks and coordinates.
- **Mop Attached** and **Do Not Disturb Active** binary sensors, a **Clean Progress** (%) sensor, and the area sensor uses the unit set on the robot.
- **Poll Interval** number (10 to 300 s, default 30) stored in the config entry.
- **Reconfigure** (change IP or account) and **reauth** (prompted when the robot rejects the stored credentials) in the config flow.
- `tapo_rv30.get_clean_records` returns the cleaning history (newest first) and lifetime totals as a service response.
- A repair issue is raised when the rooms you mapped to Home Assistant areas no longer match the current map.
- Device model and firmware version come from the robot and show on the device page.

### Changed

- Status polling goes through `multipleRequest` (one round trip instead of five), with a sequential fallback for firmware that lacks it, and retries briefly before marking entities unavailable.
- `clean_rooms`, `clean_zone` and `run_schedule` refuse with a readable message while the robot is already cleaning or paused, instead of relaying device error -3002.
- Room and map name matching ignores accents (`kupelna` matches `Kúpeľňa`).

Several of these were inspired by @jan-tdy's fork (TapoVac-ADV): batching, retries, room geometry, the repair issue and accent folding.

## v0.6.1

### Fixes

- The custom services (`clean_rooms`, `clean_zone`, `set_room_settings`, `run_schedule`, `send_raw`) now act on the vacuum you target. Before, with more than one Tapo vacuum set up, they all went to whichever was set up last, and removing one vacuum removed the services for the others. With a single vacuum the target is still optional.
- The "Map refresh failed: Device error -3016" warning while the robot is manoeuvring is now a debug message, and the refresh is retried on the next poll.

### New

- Download diagnostics (Settings > Devices & services > the vacuum > three dots > Download diagnostics) for bug reports: model, firmware, status, settings, map summary and schedules, with credentials and identifiers redacted.
- A pytest suite for the map, room, schedule and crypto helpers runs on every push.

## v0.6.0

### New

- Experimental support for AES-transport models (RV30C, RV30C Mop, and any unit that reports `encrypt_type: AES`), tracked in #25. The config flow tries TPAP first and falls back to AES, which uses python-kasa (already shipped with Home Assistant) for login and transport; every feature then works the same way. **Untested on AES hardware**: it has only been verified that TPAP devices are unaffected and that the AES path fails cleanly. Reports on #25 please. Based on @peggleg's fork.

## v0.5.0

### New

- Native `vacuum.clean_area` support: map the vacuum's rooms to Home Assistant areas in the vacuum entity's settings and clean them with the standard action (#6). Rooms from every saved map are offered, grouped by map; one run can only cover rooms on one map.
- Current Room sensor and `current_room` vacuum attribute, inferred from the vacuum's map position and refreshed every poll (#11).
- Schedules sensor with the decoded Tapo-app schedules as attributes, and `tapo_rv30.run_schedule` to start one now (#13). `run_schedule` replays the schedule's rooms/preset and settings; it is untested on hardware, as the test vacuum has no schedules.
- `tapo_rv30.send_raw` diagnostic service: send any device method and get the response.

### Fixes

- Manifest passes hassfest: keys sorted, `requests` and `Pillow` dropped from requirements (both ship with Home Assistant).

## v0.4.1

### Fixes

- `clean_rooms`, `set_room_settings` and `clean_zone` now report map, room and device failures to the caller instead of only logging them. The error names the step that failed and lists the available maps or rooms, so it shows up in the UI and in automation traces (#10).
- Map and room names are trimmed and stripped of wrapping quotes before matching. An explicit but empty `map` is an error rather than a silent fall back to the current map, and an ambiguous map name is rejected (#9).
- Invalid `suction` / `water` / `passes` values give a validation error listing the accepted values.
- The services pick up the robot's new state within a few seconds instead of waiting for the 30 s poll.

### Repository

- Releases are now created automatically when the version in `manifest.json` changes on `main`, with notes from `CHANGELOG.md`. hassfest and HACS validation run on every push.


## v0.4.0

### Fixes

- **Loads again on Home Assistant 2026.8+** (#7, #18, #23). HA removed `VacuumEntityFeature.BATTERY`; the flag and `battery_level` property are gone (the Battery sensor already covers it) and state is now reported via `activity`. Thanks to @G0LDENWASTAKEN for the same fix in #19.
- `vacuum.start` while paused now resumes instead of failing with `-3002` (#8).
- `vacuum.stop` now ends the job instead of pausing it.
- Commands no longer race the status poll (shared session is locked), and state re-polls at 2/5/10 s after a command.
- Status and error code tables now match the Tapo app (status 0-19, errors 1-45).

### New (from #22 by @cheesyturkey)

- `vacuum.locate`, `vacuum.clean_spot`
- `tapo_rv30.clean_zone`, `tapo_rv30.set_room_settings`
- Empty Bin button, consumable reset buttons
- Auto Empty, Do Not Disturb (+ start/end times), Child Lock, Carpet Boost switches
- Volume number, Last Clean sensor, Main Brush Lid / Mop Cloth hours used

### Breaking

- Requires Home Assistant 2025.1 or later.
- The **Status** sensor now shows the app's labels (Charging, Charged, Emptying Dust, Standby, ...) instead of the vacuum states. Automations matching on that sensor's text need updating; the `vacuum.*` entity states are unchanged.
- `vacuum.stop` stops rather than pauses.

Tested on an RV30 Max Plus with HA 2026.10.1. Reset buttons and `set_room_settings` are untested on hardware.

## v0.3.0

- Initial HACS release.
