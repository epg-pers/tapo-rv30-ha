# Changelog

## v0.22.0b4

### New

- **Local map restore** (`restore_map_backup`). Re-applies a downloaded map backup to the robot without the cloud: HA serves the `.bkmap` it already holds (from `fetch_cloud_map_backups`) on a short-lived LAN URL and the robot fetches and applies it with its own `mapRecovery` call. Works only with backups made by your own account (the robot checks the MD5 and the account binding baked into the file). Writes a whole map, so the robot must be docked and idle and you must pass `confirm: true`.

## v0.22.0b3

### Fixed

- Map editor: furniture now shows as a labelled box that moves as you drag it. (The robot bakes its own furniture picture into the map render, which only refreshes after Save; the labelled box makes the edit clear straight away.)

## v0.22.0b2

### New

- **Map editor** on the sidebar page's new **Edit map** tab. Draw and delete no-go zones and virtual walls, and place furniture, then save them to the robot with its own editing API (no cloud). Carpets and room names are drawn for context (view-only for now). Changes are held locally with undo until you press Save; the robot must be docked and idle to save.

## v0.21.0

### New

- **Save and re-apply your map setup** (`save_map_setup` / `apply_map_setup`, and Save/Restore buttons on the sidebar page's Maintenance tab). Snapshot a map's editable layers - no-go zones, virtual walls, carpets and room names - and write them back with the robot's own editing API. After the robot re-maps a floor, re-apply your zones and settings in one go; `apply_map_setup`'s `source_map` lets you apply an old map's setup to the new map. The map shape itself is rebuilt by the robot. (Per-room suction/water/passes stay preset-only on RV30 1.3.3 firmware.)
- **Keep local copies of your cloud map backups** (`fetch_cloud_map_backups`). Logs in to your TP-Link account and downloads the backups made with the Tapo app's backup feature into `config/tapo_rv30/map_backups`, so they survive even if TP-Link deletes them. Supports two-step login.

### Fixed

- Live map: the robot's path and dot no longer lag behind the position pulse (the card now fetches the fresh render each update instead of a cached one).

### Notes

- Restoring a backup *file* to the robot (`mapRecovery`) is cloud/account-bound in firmware and cannot be driven from a local file - see the [protocol notes](https://epg-pers.github.io/tapo-rv30-ha/protocol/) for the full investigation. `save_map_setup`/`apply_map_setup` is the local recovery that does work.

## v0.20.0

### New

- **Smart cleaning planner.** Keeps each room within a target you choose ("every 2 days", "every week", or leave out) instead of fixed times, and cleans the due rooms, most overdue first, when the house allows: nobody home (choose who counts), inside weekday and weekend windows, outside Do Not Disturb, battery above a level, not right before one of the robot's own schedules, and leaving out rooms whose motion, occupancy or presence sensors say they are in use. If someone comes home mid-run it finishes the room and docks, or keeps going if you prefer (this docking step is untested on a robot so far). It uses the vacuum's own "map rooms to areas" setting, with **Match by name** for unlinked rooms, and per-room sensor additions, removals or "ignore". Everything is set on the new **Planner** tab of the sidebar page, with a log of every decision. It starts **off and in preview mode**: it logs what it would do and never starts the robot until you turn preview off. Verified on an RV30 Max Plus in preview mode against a real house (windows, people, a motion sensor holding a room back, the preview run); starting a run uses the same call as `tapo_rv30.clean_rooms`.
- `switch.<name>_planner`, `sensor.<name>_planner_status` and the `tapo_rv30_planner` event.

## v0.19.3

### Fixed

- Services now accept device, area, floor and label targets, as the docs said. Before, only a named vacuum entity worked, and with two robots set up a device or area target was refused. Only Tapo robots inside the target are used, so an area that also holds lights or another brand's vacuum works, and a target with no Tapo robot in it gets a clear error instead of falling back to some robot.

### Docs

- New pages on the docs site: getting started, the card and dashboards, voice and automations. The changelog and contributing guide are now pages on the site too.

## v0.19.2

### Fixed

- Two entity writes at the same moment could undo each other: Water Level, Do Not Disturb, Auto Empty and Auto Update writes read the robot's current settings and send them back whole, and the read and the write now happen under one lock, so a Fan Speed change landing in between is no longer overwritten with the old value.
- A capability probe that hit a transport error (typically the robot's Wi-Fi still waking after a Home Assistant restart) used to be final, leaving a dock button or a settings switch missing until the next restart. A probe the robot did not actually answer is now repeated on later polls, up to five times.
- The map blob was LZ4-decoded up to three times per refresh (position, current room, render), in pure Python. It is decoded once and reused, which matters on a Raspberry Pi while the robot is cleaning.

## v0.19.1

### Fixed

- Card: the floor chips no longer sit under the Go button on multi-floor maps while rooms, a zone or a go-to point are selected.
- Docs: the sidebar page is split into sections with a Drive screenshot, the entities page shows the go-to tool, the services table no longer wraps service names, and the site has a proper navigation order.

## v0.19.0

### New

- **Remote drive.** The Tapo app's remote control, from Home Assistant. The sidebar page gets a **Drive** tab: take control (the robot leaves the dock), hold the arrows or the keyboard arrow keys to drive, stop, vacuum while driving, spot clean where it stands, locate, send it home. `tapo_rv30.remote_drive` is the service underneath (`enter`, `forward`, `backward`, `left`, `right`, `stop`, `exit`); the page repeats a held direction every 300 ms like the app does. Method, codes and timing from the app (`directionControl`, see protocol.md), verified on an RV30 Max Plus.
- **Go to a point from the card.** A new map tool: tap where the robot should go and press "Go here" (`tapo_rv30.go_to`, verified earlier). Hidden on robots without go-to-point.
- The vacuum entity carries `goto_point` and `remote_control` attributes so cards can hide what a robot cannot do.

## v0.18.0

### New

- **Tapo Vacuum sidebar page.** One page with everything: the live map card, a **schedules editor** (add, edit, enable, disable and delete the robot's own schedules with a form: time, days, rooms or preset or whole house, levels), **history and statistics** (cleans per day, minutes per week, lifetime totals, the recent runs), **rooms** with freshness bars and one-tap cleaning, **maintenance** (consumable life, bin, resets, dock actions) and **settings** (every switch, select and number). Several robots become tabs. Turn it off in the integration's options if you only want the card and entities.
- Integration **options** (Settings, Devices and services, Tapo Robot Vacuum, Configure): show or hide the sidebar page.
- Preset buttons expose `preset_id` and `preset_name`.
- **Do Not Disturb aware schedules.** The robot keeps a schedule whose start time is inside its Do Not Disturb window but never runs it (verified: it stays docked). The schedules sensor marks such schedules `blocked_by_dnd` and carries the window (`dnd`), the sidebar page flags them in the list and in the editor and asks before saving or enabling one, and `add_schedule` / `set_schedule` refuse them unless `ignore_dnd: true`. The Do Not Disturb times are editable on the page's Settings tab.


### New

- **Per-room "last cleaned"**: every finished run's map is folded onto the current map's rooms, so each room knows when it was last cleaned and what share of it the robot covered (runs that only crossed a room do not count). Kept across restarts; old records are backfilled a few per poll while the robot is docked. Exposed as `rooms_last_cleaned` and on each `room_geometry` entry of the map camera.
- **Card status panel**: the history button opens the last clean map, the recent runs (when, area, minutes, how started, preset) and consumable life bars. Holding a room shows its last-cleaned line.
- **Dashboard strategy** `custom:tapo-rv30`: one line of dashboard config builds a complete view per robot.
- The map camera carries `last_clean` (record details) and `last_clean_url`; the vacuum entity carries `consumables` (percent life left per part).


### New

- **Discovery**: Home Assistant offers the robot when it sees its DHCP lease (TP-Link MAC prefix E0:D3:62 so far; other prefixes welcome via an issue) and the robot answers on the TPAP port. An existing entry follows the robot when its IP changes.
- **Voice**: Assist sentences registered by the integration: "vacuum the kitchen and the lounge", "clean everywhere", "send the robot home", "stop the vacuum". Rooms resolve against the current map; the reply names anything it did not recognise.
- **Device triggers** for clean started / finished / error, so the events appear in the automation editor's device picker. Events now carry `device_id`.
- **Blueprints**: notify with the Last Clean Map when a run finishes; clean when everyone has left. Import badges in the README.
- **Icons**: the vacuum entity wears its own state-coloured robot picture; problem and charging binary sensors and every service get icons through icons.json. (Per-state sensor icons are not possible without renaming the sensor states, which would break automations, so those stay as they are.)
- **Furniture** on the map is now drawn as filled, anti-aliased illustrations (beds with pillows, sofas with cushions, tables with chairs, appliances, plants, toilet, pet items) instead of line glyphs.


### New

- **Furniture drawn on the map**: every item the app knows (beds, sofas, tables, TV cabinet, wardrobe, bedside table, fridge, washer, air conditioner, plants, toilet, pet house, litter box, pet bowl) gets its own glyph and label, rotated with the item. The glyphs are the integration's own drawings. Full type code table in the README.

### Changed

- Carpet Boost documented as the app's carpet cleaning preference (`setCarpetClean` boost / normal and `setCarpetAutoBoost` are the same setting on the RV30 Max Plus), so no separate select was added.


### Changed

- The Matter setup code is now its own **Matter Setup Code** sensor (diagnostic, off by default) instead of an attribute buried on the Matter sensor; the QR payload is its attribute.

## v0.14.0

### New

- **Matter**: a diagnostic sensor (off by default) with the robot's pairing state (`Not paired` / `Pairing window open` / `Paired`), paired ecosystems, time left in the pairing window, and the robot's fixed setup code and QR payload; an **Open Matter Pairing Window** button (`startCommission`); and `tapo_rv30.remove_matter_fabric`. Only created on robots that report the `matter` component. Status and setup-info reads verified on an RV30 Max Plus; the button and the remove service follow the app's code and are untested on hardware. See the README's Matter section, including why the code does not change but the window does.


### New

- **Last Clean Map** image entity: the newest clean record rendered from the robot's own copy (`getCleanRecordExtraInfo`): cleaned cells in blue, skipped rooms in grey, the driven path, start (green) and end (red) points, dock. Read once per record and only while the robot is not working. Record details (area, minutes, start type, map) are its attributes.
- **Schedules from Home Assistant**: `tapo_rv30.add_schedule`, `set_schedule` and `remove_schedule` drive the robot's own schedule list (`addScheduleRule` / `editScheduleRule` / `removeScheduleRules`, bodies verified on an RV30 Max Plus). Days accept Mon..Sun, daily, weekdays or weekend; rooms, a preset or the whole house; optional suction / water / passes. Repeating schedules only: in testing the robot stored a one-off rule on a different date than asked.


### Fixed

- `set_room_settings` on RV30 Max Plus firmware 1.3.3 failed with "Device error -1001": that firmware rejects the app's own per-room write, so it never worked there (it was listed as untested since 0.4). It now explains that and points at the alternatives.
- `clean_rooms` takes optional `suction`, `water` and `passes` for the run. The card's long-press room sheet now starts a clean of that room with the chosen levels instead of trying to save them.


Method names and value tables in this release were read from the Tapo Android app (3.22.105) and then verified on an RV30 Max Plus.

### Changed

- `tapo_rv30.send_raw` now refuses methods the integration does not itself use while the robot is cleaning, returning or paused, unless `force: true`. See the README protocol notes for the map loss that prompted this.
- Settings entities re-read the robot again 2.5 s after a write, as it can answer with the old value for a moment.

### New

- **Go to point**: `tapo_rv30.go_to` (x, y in map mm) on robots that report `goto_point`; `vacuum.stop` now cancels a go-to in progress.
- **Auto Firmware Update** switch (the robot's own scheduled update, `get/setAutoUpdateInfo`).
- **Auto Empty Mode** select (Smart / Light / Balanced / Max) for self-empty docks, via `setDustCollectionInfo` `dust_collection_mode`.
- Furniture is listed in `map_geometry.furniture` (px and mm outlines, type code and name; the full code table was read from the Tapo app, see README).

## v0.11.0

### New

- **Cleaning path** drawn on the map while the robot works (read with `getPathData`, decoded here for the first time) and kept until the next run starts.
- **Card**: floor switcher when the robot has several maps; in zone mode, tap a saved zone to clean it; long-press a room for its suction / water / passes.
- **Firmware** update entity (read-only, from the robot's own update check; installing is left to the app on purpose) and a **Wi-Fi Signal** diagnostic sensor (disabled by default).
- **Repair issue** when a robot that used to answer has failed every poll for 10 minutes, pointing at the known firmware regression and the fix (power-cycle).
- **Card** `rotate` option (0 / 90 / 180 / 270) for maps the robot scanned sideways; taps and zone drags still land where you point.
- **Wash Mop / Dry Mop / Remove Hair** buttons for Omni docks, created only when the dock answers the matching command (method names from the cavefire and jan-tdy forks; untested here, the author's RV30 has no Omni dock).

### Changed

- **Adaptive polling**: 10 s while cleaning or returning, your configured interval otherwise.
- The map is now a PNG with a transparent background, so it looks right on light and dark themes in the card and in picture cards.
- Display name is now "Tapo Robot Vacuum" (integration, HACS, card picker). The `tapo_rv30` domain, entity ids and card type are unchanged.

## v0.10.0

### New

- **Bundled Lovelace card** (`custom:tapo-rv30-card`). The integration serves it and registers it as a dashboard resource itself, so there is nothing else to install. Live map with tap-to-select rooms and a drag-to-draw zone (taps resolve through a lossless room mask the integration serves, so odd-shaped rooms work and there is no calibration), status / room / battery / progress header, problem banner, preset chips, and start / pause / stop / dock / locate / empty-bin controls. Theme-aware, with a visual editor. Plain JavaScript, no build step.
- `rooms_mask_url` attribute on the map camera, and `/api/tapo_rv30/<entry_id>/rooms.png` (authenticated) for anyone building their own card.

## v0.9.0

### New

- **Events**: `tapo_rv30_clean_started`, `tapo_rv30_clean_finished` (with the robot's record of the run: area, minutes, bin emptied, preset name) and `tapo_rv30_error`, for notifications and automations. See `examples/automations.yaml`.
- **Problem** binary sensor (on while the robot reports an error, with code and text as attributes) and **Replace <consumable>** sensors that turn on below 10% of service life.
- **Total Cleans**, **Total Area Cleaned** and **Total Cleaning Time** sensors (`total_increasing`, so long-term statistics work).
- **Map Image** entity alongside the camera; the frontend updates it the moment the map changes.
- A generic example dashboard (`examples/dashboard.yaml`) with a mock-up screenshot, and example automations.

### Changed

- Service names and descriptions moved to `strings.json` (Home Assistant's translation format); `services.yaml` keeps the selectors.
- `jarvis_dashboard.yaml` (the author's personal dashboard) is superseded by the example and removed.

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
