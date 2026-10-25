# Changelog

## v0.34.0b1

### Added

- **Map rotation.** Turn a map's display by quarter turns, stored on the robot exactly as the Tapo app stores it (`rotate_angle`), so Home Assistant and the app always show the map the same way round.
  - A **Map Rotation** select (0 / 90 / 180 / 270, clockwise) for the current map, turn buttons on each map in the sidebar page's Settings tab, and `tapo_rv30.set_map_rotation` for any map. Only the map's id and angle are sent.
  - Everything turns together: the map picture (room labels stay upright), the room mask the card uses for tap-to-clean, room outlines and the dock, the live robot and path, saved zones and furniture, the calibration points for third-party map cards, the Last Clean Map and clean map history. The card's zones and go-to taps and the map editor convert through the same rotation, so a zone drawn or an edit saved on a turned map is exactly what it would be on an unturned one.
  - Display only: rooms, zones, furniture, schedules and cleaning are unaffected.

## v0.33.1

Fixes from a review of the map rename in 0.33.0.

### Changed

- **`rename_map` is admin only**, like the other services that rewrite what is on the robot. The Rename button is disabled for other users.
- **The map to rename must be named in full, or by id.** A partial name could land on the wrong map ("Gard" renaming "Garden" instead of "Garage").
- **A new name may not equal, contain or be part of another map's name.** Services that take a map by name match exactly first and then by part, so such a name could silently move existing automations to a different map. (Two maps called "Floor 1" and "Floor 10" therefore cannot coexist through a rename.)

### Fixed

- Whether the map is saved is checked against a fresh read of the robot's maps, not the cached list, which can lag a just-finished mapping run.
- Names are stored composed (NFC), and control or invisible characters (such as zero-width spaces) are refused, so the 32-character limit counts the same way the app does.
- If the robot does not confirm the new name, Home Assistant still refreshes its maps rather than showing stale names until the next map read.
- The Rename button edits the name in place instead of opening a browser prompt, which the mobile app's web view may not show.

## v0.33.0

### Added

- **Rename a map.** `tapo_rv30.rename_map` (`map`: name or id, `name`) and a **Rename** button in a new **Maps** card on the sidebar page's Settings tab rename a saved map on the robot, the same call the Tapo app makes (only the map's id and new name are sent). The robot must be idle; a name over 32 characters, unchanged, or already used by another map is refused; the robot is read back to confirm the new name.
  - Checked on an RV30 Max Plus (firmware 1.3.3): renamed and back again, with nothing else on the robot's map entry (rotation, lock, saved state), the schedules, presets, area mappings or room freshness changing.
  - Schedules, presets, room freshness, the planner, area mappings, saved map setups and clean map history all follow a map by its id, so a rename does not affect them. Automations that pass the old name as `map:` to `set_map`, `clean_rooms`, `add_schedule` or `apply_map_setup` need the new name; passing the map id avoids that.

## v0.32.2

### Fixed

- **Robots that prove their identity without TLS (tls 0 with device attestation, seen on RV30 Max Plus Gen2 firmware 1.3.5) can be set up again.** They send their attestation certificates as base64 of PEM text, the format the Tapo app reads; the integration parsed the decoded text as DER and setup failed with "DAC verification failed: error parsing asn1 value ... Tag { value: 13, constructed: true ... }", followed by a needless re-authentication prompt. Base64 PEM, plain PEM and base64 DER are all read now.
- The attestation chain is accepted under either of the two TP-Link device roots the Tapo app pins (TP-LINK SYSTEMS and TP-LINK GLOBAL DEVICE ROOT CA), not just the first. The TLS pin is unchanged.

## v0.32.1

### Fixed

- The test suite runs under CI's plain `pytest tests` again (a new test imported a helper in a way only a local run could find). No change to the integration itself.

## v0.32.0

### Security

- **The Matter pairing code is no longer in entity state.** The Matter Setup Code sensor is removed and the Matter sensor no longer carries `setup_code` / `setup_payload` attributes: entity state is readable by every user and kept by the recorder, and with the Open Matter Pairing Window button any user could have paired the robot to their own ecosystem. The code now comes only from the new admin-only `tapo_rv30.get_matter_setup_code` action (it is also printed on the robot). If you had those sensors enabled, older values may still be in the recorder's history: `recorder.purge_entities` on them clears it. Raised in the review of this integration's HACS submission.

### Added

- **Clean map history.** The History tab's runs each have a **Map** button: where the robot went on that run (cleaned cells, path, start, end and dock), with **Download** and **Forget**.
  - A run's map is kept when the integration reads the run anyway (for the Last Clean Map and room freshness), so it costs no extra calls to the robot.
  - Kept maps open from Home Assistant's disk, so they work while the robot is cleaning or offline, and they outlast the robot's own short list of recent runs.
  - Only what drawing needs is kept, compressed (a one-room run took 9 KB), under `config/tapo_rv30/clean_history/<robot>/`. Drawn maps are held in memory for quick reopening.
  - A run still on the robot but not kept is marked "on robot" and read from it when opened (once it is docked), then kept.
- **Retention controls.** The **Clean Map History** select (Off, 1 week, 1 month, 3 months (default), 1 year, Forever) and the **Clean Map History Limit** number (200 by default, 10 to 1000) decide how long and how many. They are on the History tab and in Settings, and work from automations. Off deletes the kept maps. Diagnostics show how many are kept and the space used.

## v0.31.1

### Fixed

- Handing a map backup back to the robot during a restore no longer checks the file on Home Assistant's event loop (a blocking call on every request the robot makes). A missing file still answers 404.

## v0.31.0

A fifth bug hunt: the last release's own changes, the protocol and transport line by line, time and state machines, map geometry (including the map editor problem reported with a screenshot), what happens when things go wrong, and the docs and packaging. Every finding was checked by separate reviewers trying to disprove it.

### Fixed

- **A passing TLS hiccup no longer asks you to re-authenticate.** On a robot with the pinned certificate, a robot reboot or Wi-Fi drop during a new handshake was taken for a wrong certificate: Home Assistant asked for the password again and stopped polling until you did. Only a certificate that is really refused counts now (a wrong clock does not either); anything else is retried, and the "stopped answering" repair appears if it lasts.
- **Run tracking rebuilt.** 0.30 could treat a plain "return to dock" from standby (or after go-to or remote drive) as a clean and refuse map writes for 8 hours. Now only a real clean opens a run, a robot docked part way through to recharge or (Omni docks) to wash its mop stays busy, one run gives one `clean_started` and one `clean_finished`, a run in progress is picked up after a restart, and after a run map writes wait at most 15 minutes for its record. Go-to and remote drive no longer fire clean events. Start, presets and `clean_area` are refused while the robot is docked part way through a run (press Stop first to start a different clean; the card's Stop button is available then, and the vacuum's new `run_busy` attribute says why), and the planner no longer logs "Finished" then.
- **Map editor furniture.**
  - New items get the real-world size of their type instead of all being 700 x 500 mm, and can be resized with a handle.
  - They are saved with their corners in the robot's own order (they would have drawn upside down) and with their own ids.
  - Furniture is drawn under the zones, lighter, so a no-go zone inside a piece of furniture can be seen and selected.
  - The type list matches the integration's (all 19 types).
- Everything drawn on the map from millimetres (zones, furniture, path, robot, go-to and zone taps, calibration points) sat half a cell (25 mm) off. The robot dot and live path between full map reads are drawn in the map image's own frame, and a rare spike to the map origin is gone.
- The card's room sheet shows the robot's current levels for a room with none of its own, so what is highlighted is what the clean uses.
- A password change now asks for re-authentication on RV30C (AES) robots and on firmware without batched requests, instead of trying to log in dozens of times a minute.
- A reply that cannot be read after a write is no longer answered by sending the write again (a schedule or preset could be added twice). On the newer protocol, message numbers are reserved and saved before sending, so a reload or crash does not send two messages under the same key and number (if the save fails, a warning is logged once and the old session copy is removed, so a new session is made instead), and a used-up counter starts a new session instead of stopping the integration. A robot asking for an absurd number of password rounds is refused.
- A robot that drops off Wi-Fi part way through a poll no longer holds it for minutes, and a failed settings read during setup no longer leaves the robot without its settings entities.
- The automatic restore finish retries after a failed read instead of failing silently; `apply_map_setup` reports a failed read clearly.
- The planner does not try to start a clean while the robot is not answering (it filled its history with errors).
- The TP-Link cloud token can no longer appear in an error message.
- The "stopped answering" repair is removed when the integration is unloaded or deleted.
- Diagnostics show how the robot numbers its replies, to decide later whether replies that do not match their request can be refused.

### Docs and packaging

- Consumable sensors are documented as hours left; the idle poll default is 30 seconds; entities a fork leaves behind have to be deleted by hand; entity names, the Drive tab and device trigger labels corrected; the missing 0.12 to 0.17 sections are back in this changelog.
- The docs site is rebuilt when a release changes the changelog. Debug logging includes python-kasa (RV30C), the integration is listed as a device, and a missing python-kasa internal no longer breaks RV30C robots. CI tool versions are pinned.

## v0.30.0

A fourth bug hunt, from new angles: upgrades and stored data, the last release's own changes, other models and households, the sidebar page and card in a browser, the service contract, a safety audit of every write to the robot, and performance over weeks. Every finding was argued for and against by separate reviewers; only what held up was fixed.

### Safety

- **A clean can no longer start while a map write is running.** The vacuum's Start, spot clean, `vacuum.clean_area`, voice and preset buttons are now refused (try again shortly) while map setup, the map editor or the automatic restore finish runs, as the services already were. Map writes also ask the robot itself whether it is working, instead of trusting the last poll.
- **A robot that docks to recharge part way through a clean is still cleaning.** It used to look finished: map writes were allowed and `clean_finished` fired early. Now the run stays open until the robot records it (map writes and the restore finish wait), one run gives one start and one finish event, and the planner does not start another clean meanwhile.
- **Rooms picked on one map are never cleaned on another.** `clean_rooms` and `vacuum.clean_area` check which map the robot is on right now and refuse rooms from another map (room numbers restart on every map, so they would be other rooms). Switch with `set_map` first.
- **Voice no longer cleans a room from part of a word.** "Clean it" cleaned the Kitchen ("it" is in "kitchen") and "clean the room" a Bedroom. A partial name now has to be the start of a word, three letters or more ("clean the bath").
- With several robots, backups and setups saved by versions before 0.28 (in the shared folder) are no longer offered to every robot: there is no telling whose they are, and restoring one robot's map onto another also added its schedules.
- `send_raw` refuses any name that is not a plain method name (hidden characters could make a blocked call look different) and a few more quick-setup, factory and map-deleting calls.
- A preset button whose preset was deleted in the app is removed, and a button never runs a different preset that reused the id.

### Fixed

- The planner's "Match by name" works with area and room names in any script (Cyrillic, Chinese, Greek...); before, they all matched one area. A clean that fails no longer wipes the record of one that started at the same moment, and a planner file the integration cannot read no longer stops the robot from setting up.
- `run_schedule` and `run_preset` switch back to the robot's map when the robot refuses the clean.
- The stored connection security follows a firmware update that adds security (the pinned certificate, device attestation), never one that removes it.
- A map setup file left half written by a crash no longer breaks `apply_map_setup` and the restore finish (files are now written safely, and a damaged one falls back to another copy). A Home Assistant restart while a restore is being applied still finishes it. A map write starting during the automatic finish now postpones the finish instead of dropping it.
- Merging or deleting rooms in the app no longer freezes the map setup snapshot, and a run on another floor is counted for that floor's rooms once it is active again.
- A second setting that answers late gets its entities too. A value the robot sends as infinity no longer breaks a poll.
- Robots without a mop get no Water Level select, and entities for parts a robot does not have, left over from 0.28, are removed.
- RV30C (AES): a refused command no longer reconnects and repeats, and batching is remembered as unsupported.
- `vacuum.set_fan_speed` with an unknown speed now says so; `water: off` written without quotes works; the `send_raw` example works; planner preview events carry `by`; a clean for two robots checks both before starting either.
- `restore_map_backup`, `apply_map_setup`, `save_map_setup` and `fetch_cloud_map_backups` work in scripts and automations without `response_variable`, as in the docs.
- The "Clean when everyone has left" blueprint counts someone in a named zone (Work, School) as out.
- `add_schedule` and `set_schedule` accept `room_ids`.
- Sidebar page:
  - Planner window times, and the Settings tab's times (Do Not Disturb), are saved when you leave the field, not on every keystroke (typing 18:00 could save 01:00 to the robot).
  - The schedule editor picks rooms by id, so same-named and unnamed rooms work, and app-made one-off schedules can be edited and show their date.
  - A refused setting shows the robot's real value again; History says when it could not load; the Planner tab fits a 320 px screen.
- Card:
  - The room sheet only sends the levels you change (they become the robot's defaults), opens with focus and closes on Escape.
  - A long press no longer opens it after your finger has moved.
  - The selection overlay is cached instead of redrawn every frame, a short outage no longer clears the selection, history is not fetched twice, and the hint no longer hides under the tools on phones.
- Card, dashboard and sidebar page find the entities of a second robot with the same name (ids ending in `_2`).

### Performance

- The full map and settings read runs every 5 minutes as intended, also while cleaning (it ran every 100 seconds).
- A docked robot's live map image is not redrawn and re-encoded when nothing changed, and the per-poll image is encoded faster.
- The map camera's large attributes are no longer written to the recorder database on every poll while cleaning.
- The Backups tab remembers thumbnails and details of files that have not changed.

## v0.29.0

A third bug hunt, with new angles: hostile and odd robot data, network faults, things happening at the same time, a brand new user, missing tests and a check of the last round's fixes. Every finding was argued for and against by separate reviewers, and only what held up was fixed.

### Security

- **The robot's connection security is remembered.** At setup (or on the first start of this version) the integration stores how the robot secures its local connection. A later answer offering less, such as no TP-Link certificate or the MAC-derived passcode, is refused and Home Assistant asks you to re-authenticate, instead of following whatever answered in the robot's place. See troubleshooting if you reset or replaced the robot.
- The sidebar page escaped all text, but a few numbers from the robot (room passes, consumable percentages, number limits) reached the page raw. They are now forced to numbers.
- A corrupt or hostile map reply or backup file can no longer use up Home Assistant's memory (map size and backup unpack size are capped), and a damaged backup file no longer breaks the Backups tab.

### Fixed

- Two actions at once on the same robot (two room cleans, a clean during a map setup write, two schedule edits) no longer mix: each clean start is one step, map writes take turns and cleans wait for them, and `set_schedule` edits a fresh copy of the schedule.
- After a reload, the old connection sends nothing more (two connections on one session could clash), the planner stops before the entities go, and a restore that was running carries on with the new connection.
- `run_schedule` switches to the schedule's map first, and only puts the old default levels back when the clean certainly did not start.
- Odd values from the robot (text where a number belongs, a missing name, a single error code instead of a list, schedules paged oddly) no longer break a poll. Batched reads that the robot refuses part way are read one by one instead of turning batching off.
- A robot with no map yet no longer re-reads all settings every poll or logs the map warning every poll. A setting that answers only now and then no longer reloads the integration each time.
- The robot's time zone, if Home Assistant does not know it, no longer stops setup.
- Map setups: the summary counts only zones actually added; a schedule whose preset is not in the saved setup is skipped; an unnamed saved room never blanks a name; a snapshot is still taken when another map's preset could not be read.
- Planner: waits when the battery level is not known yet, follows app-made one-off schedules, drops a run from hours ago after a restart, and records a run before the robot answers.
- The vacuum shows Error when the robot stops with an error code. A switch flipped during a poll no longer flips back for a moment.
- Voice: robot names with punctuation work ("R2-D2"), a name only counts as a whole word ("Bot" is not in "robot"), the longest name wins, and two robots with the same name are asked about. Registration works on Home Assistant releases that take trigger details.
- Setup: an RV30C (AES) address that is another Tapo device is refused with a clear message; adding a robot by hand works while its discovery is open; a lease from another integration's device no longer hides a new robot; reconfigure keeps the password when left blank; ignored or disabled entries no longer keep the sidebar page.
- Actions sent while a robot is still connecting say so instead of "not a Tapo RV30 entity".
- Robots without a mop or some parts get no entities for them. The water level and auto-empty mode selects have translated states. Device triggers read properly. The repair link points at the right README section.
- Dashboard strategy and sidebar page: sensors are matched by exact name (Planner Status is no longer taken for Status; Last Clean is shown); presets are not confused with other buttons; entities without a friendly name no longer break the Maintenance and Settings tabs; room buttons send their map, so a button left from another floor fails clearly instead of cleaning a room there. The card's room sheet only sends levels it offers.
- Docs: entity names, `clean_rooms` `map_id`, card images, service icons and field descriptions.

## v0.28.0

A second full bug hunt, by five fresh reviewers. Every finding was checked by a separate reviewer trying to disprove it, and by tests on a robot where possible; only what held up was fixed.

### Changed

- **Each robot keeps its own map backups and saved map setups**, in `config/tapo_rv30/map_backups/<robot>` and `map_setups/<robot>` (the robot's MAC). With two robots, one could be offered, and sent, the other's backup. Files saved by earlier versions are still found.
- **Services stay registered while a robot is still being set up**, so an automation gets a clear error instead of "action not found" during a setup retry.
- Area sensors always report m2 (what the robot measures) with the area device class, so Home Assistant can show them in ft2 if you prefer. Before, a ft2 setting in the app only changed the label.
- `clean_rooms` accepts `room_ids`, which the card and sidebar page now send: unnamed rooms (as after a restore) and rooms that share a name can be cleaned. A partial room name that fits several rooms is refused rather than cleaning them all.
- Voice: say the robot's name ("tell Jarvis to clean the kitchen", "send Jarvis home", "stop Jarvis", "vacuum the kitchen with Jarvis"). With several robots and no name, the one that has the rooms (or is working) is used, or Assist asks which. "Vacuum pause" pauses and a trailing "please" is ignored.

### Fixed

- Robot schedules and Do Not Disturb are compared with the robot's own clock (its region), not Home Assistant's, and a schedule just after midnight counts as soon.
- Map writes (restore, apply setup, the editor, the automatic restore finish) also wait while the robot is driving home, and the automatic finish asks the robot itself before switching maps, so it can never run under a cleaning robot after a restart.
- `apply_map_setup` / the restore finish: zones are matched by outline, so renumbered zones are not rewritten and zones drawn since are kept; a schedule whose rooms are not on the map is skipped and said; a preset recreated without some rooms says so; whole-house schedules are not added twice; a refused or lost map switch is reported properly and the map is switched back.
- Restore: one missed progress read no longer ends it, and if the robot is still applying when polling ends, the backup stays served and the automatic finish still happens.
- Planner: a run in progress and a preview survive a restart; changes made just before a reload are not lost; "finish the room, then dock" waits until the robot is in a room (unnamed rooms count); a failed "Clean due rooms now" is reported instead of looking like it worked.
- `set_schedule` can change app-made one-off schedules and keeps the app's pre-start reminder. `run_schedule` puts the previous default levels back if the start fails.
- Level writes send only what changed (verified on 1.3.3); a status the robot did not report shows as unknown instead of 0% battery or Max.
- Setup: a failure part way through (voice, the sidebar page or later) no longer leaves the integration half set up and unable to reload; deleting the integration removes its stored planner, room history and session; a robot whose cached certificate mode was pinned is re-discovered through the pin.
- Two robots that swap network addresses each keep following their own robot.
- RV30C (AES): a write whose connection was refused outright is sent again (it never reached the robot).
- Room freshness waits for a run's own map instead of dropping runs from another floor, and does not re-download records while no map is loaded. `vacuum.clean_area` works when another floor's map cannot be read.
- Sidebar page and card: driving stops and is rebuilt after the page is hidden and shown again; editing a schedule whose preset was deleted no longer moves it to another preset; planner window times keep both ends; the card uses the map image even if the map image entity is disabled; History and planner replies cannot show the wrong robot, and History refreshes after new runs; keyboard focus survives polls; the map editor handles a drag released outside the map; switches have accessible names; primary buttons are styled.
- Docs: local restore, deleted map ids and schedule id examples corrected; admin-only services apply to scripts run by non-admin users too.

## v0.27.0

A full bug hunt across the integration. Everything below was found by reading and testing the code, then fixed.

### Security

- The card put room and preset names into the page unescaped, so a name could run script in the browser of anyone viewing it. Everything from the robot is now escaped.
- Diagnostics downloads redact the device details (MAC, IP, Wi-Fi name, location) and the Matter setup code, which the raw status and settings sections still carried.
- `send_raw` checks every call inside a `multipleRequest`, so the blocked onboarding and factory calls can no longer be sent that way. Busy checks apply to them too.
- Services that can wipe or rewrite what is on the robot need an admin user: `send_raw`, `restore_map_backup`, `apply_map_setup`, `save_map_setup`, `fetch_cloud_map_backups`, `delete_preset`, `remove_schedule`, `remove_matter_fabric`. Automations and scripts are unaffected. The panel disables those controls for other users.
- Environment settings such as `REQUESTS_CA_BUNDLE` no longer widen the TP-Link certificate pin. A robot that advertises device attestation but sends no proof is now logged as a warning.

### Fixed

- A command is only sent again after a lost reply when it certainly never reached the robot. Before, most dropped connections re-sent writes (a clean could start twice), and the RV30C (AES) client could send one write up to 8 times.
- RV30C (AES): one getter the robot does not support no longer makes every status poll fail; sessions, sockets and threads are closed on unload and after a failed setup.
- Planner: "Clean now" no longer docks after the first room because someone is home; a planner run only docks for someone who arrives during it. A preview run no longer uses up the day.
- `restore_map_backup` waits for the robot to finish (it stopped at "running"), so a restored deleted map now finishes on its own. The pending finish survives a restart, and the automatic snapshot cannot overwrite the setup it needs meanwhile.
- `apply_map_setup` and the map editor switch the robot back to the map it was on, and the editor keeps the robot's own fields on existing no-go zones and walls. One refused preset or schedule no longer stops the rest.
- One failed settings read no longer drops that setting (the planner could ignore Do Not Disturb); overlapping polls no longer fire `clean_finished` twice; a failed map read retries the map alone; entities for settings or dock actions that only answer after a restart are added.
- Saving the integration options no longer resets the poll interval; reconfigure refuses an address another entry already uses; the unreachable repair clears after a reload; firmware version updates after a robot update.
- Room freshness: runs that could not be folded in yet are retried rather than skipped forever.
- Services: `update_preset` finds rooms on the preset's own map; `run_schedule` accepts ids like "1" and checks the robot is free before changing levels; ambiguous partial room names are refused instead of cleaning every match; `passes` must be 1 to 3; `clean_zone` explains bad zones; `save_map_setup` keeps a good setup unless forced; a missing backup folder gives a clear message; `remote_drive` is removed with the integration.
- Schedule restore compares map, rooms and preset, not just time; schedules on another floor show their own room names; long schedule lists are read past the first page.
- Voice: "pause the robot" pauses instead of stopping; ambiguous room names ask which one; "vacuum go home" and "clean the whole house" do what they say.
- Card: presets deleted on the robot no longer leave a dead chip; no blank card after editing its config or when the vacuum appears late; no animation running after the card is closed; 90 and 270 degree rotation fits; selections clear on a floor switch.
- Panel: switching tab while History is loading no longer throws an error. Forms are no longer wiped by every poll while the robot works; the Planner tab no longer crashes without a map; editing another floor's schedule no longer moves it to this floor; an offline robot is still listed; remote drive state resets when switching robots; history charts use local days; planner live updates survive a reload.
- Cloud backup fetch: a mistyped verification code can be retried.
- Docs: the Sweep Walk field is `sweepWalk`.

## v0.26.3

### Fixed

- `vacuum.clean_area` copes with area mappings left over from old maps. Home Assistant keeps every room ever mapped to an area, so after a remap or a lost map an area could point at rooms the robot no longer has, and the whole clean was refused. Those rooms are now skipped (and logged), the active map wins when the rest spans several maps, and you only get an error, telling you to redo the area mapping, when nothing valid is left.

## v0.26.2

### Fixed

- Robots that report `tls: 0` on port 4433 (seen on an RV30 Max Plus Gen2) connect again. TLS mode 0 was taken to mean plain http, which the robot drops on that port; https is now kept on the port discovery answered on, and plain http is only used for a different port the robot names. Device attestation (DAC) is still checked for these robots.
- The websocket commands that change things (planner settings and actions, including matching areas, and applying map edits) now need an admin user. Reading stays open to every user.
- The vacuum client is created off the event loop (its constructor makes the session cache folder).
- The last clean map is PNG-encoded in the executor instead of on the event loop.

## v0.26.1

### Fixed

- `vacuum.start` carries on with any paused job (mapping, going to a point and exploring too, not only a paused clean), does nothing when the robot is already cleaning, and says why when it is under remote control or going to a point, instead of passing on the robot's -3002.
- A room, zone, spot or preset clean asked for while the robot is busy is refused with a readable reason on every path, including `vacuum.clean_area` and `vacuum.clean_spot`, not only the services.
- A command whose reply is lost (read timeout) is no longer sent a second time, so a clean cannot start twice; the next call starts a fresh session. Reads are still retried.
- The Clean Passes and Water Level selects, and the preset and map setup services, report device errors as a readable message instead of a traceback.

## v0.26.0

### New

- **Make, edit and delete presets from Home Assistant.** `create_preset` (name, rooms, optional suction / water / passes / clean order), `update_preset` (rename, change rooms or levels; anything not given is kept) and `delete_preset` (needs `confirm: true`). They use the same robot calls as the Tapo app, so presets show up in the app and run with `run_preset`. This is also the way to keep per-room levels on firmware that rejects `set_room_settings`.
- **Robot notices as events.** The robot's prompts (dust bag full, area unreachable, cleaning finished, emptying done, water tank empty and others) fire `tapo_rv30_prompt` once each time they appear, with `prompt`, `description` and `code`. Also available as a "gave a notice" device trigger, and the active ones are on the vacuum's `prompts` attribute.
- **Reset Mop Cloth** button, next to the other consumable resets (the usage sensor already existed).
- A restore of a deleted map now finishes on its own: once the restored map is saved in the Tapo app, its room names, zones, furniture, presets and schedules are put back from the saved setup and a notification says so.

### Docs

- Protocol notes now cover presets, status prompt codes, the clean start fields (`clean_mode`, `start_type`, `force_clean`, `clean_type`, density), `setCleanAttr` types, component gating, the calls 1.3.3 does not know, and the factory and debug calls that must never be sent.

### Fixed

- Omni dock wash, dry and hair-cut buttons send `{"switch": true}`, the parameter the Tapo app uses. The old per-action keys were taken from other integrations and may have been ignored.

## v0.25.0

### New

- **Recover from losing every map.** `restore_map_backup` now works when the map is gone from the robot: pass the lost map's name (from its saved setup) or id, and any map on the robot - even a throwaway quick mapping run - carries the restore. The robot brings the backup back under the map's original id, so presets, schedules and history line up again. The response says where it landed and whether it needs saving in the Tapo app, and gives a clear message if the robot has no maps at all. The Backups tab's Restore button works the same way.
- **Automatic map setup snapshots.** Each map's room names, no-go zones, virtual walls, carpets, furniture, presets and schedules are saved to `config/tapo_rv30/map_setups` whenever they change, from data already polled (no extra robot calls). A snapshot that looks like a lost or freshly restored map never replaces a good one, and the last 30 versions are kept in `map_setups/history`.
- **`apply_map_setup` puts everything back**, not just zones and names: furniture, plus any missing presets (recreated) and schedules (re-pointed at the recreated presets). Only what is missing or different is written; `dry_run: true` reports what it would do. The response also lists what the saved snapshot holds, so the safety net can be checked.

### Fixed

- `send_raw` refuses onboarding, system and factory calls (`setInheritInfo`, quick setup, reset, reboot, firmware, wifi and others), even with `force`. Calls from the first-time setup family came minutes before this robot lost every map.

## v0.24.0

### New

- **Auto-change Map** switch. Turns on the robot's automatic map selection, so it picks the saved map that matches the floor it wakes up on. Found by going back through the robot firmware and confirmed live on 1.3.3.

### Docs

- Full TPAP endpoint map in the [protocol notes](protocol.md): every method the firmware dispatcher carries, cross-checked against the live robot and marked by what it actually supports, plus the map/clean actions still to wire up and confirmation there is no camera/video endpoint.

## v0.23.1

### Fixed

- **Per-room "last cleaned" date** now updates for every kind of run. Room cleans and scheduled/auto-area cleans store the map as a full room segmentation rather than a cleaned-cell mask, so the old coverage check (which only counted cleaned-cell markers) never registered them and the room's date stayed stale. Coverage is now read from the robot's actual path, which is reliable across all record formats and correctly tells a single-room clean from a whole-floor one. The saved history is re-folded once on upgrade so existing dates correct themselves.

## v0.23.0

### New

- **Backup map viewer** on the sidebar page's new **Backups** tab. See every map backup Home Assistant holds as a thumbnail grid, tap one to view it full size, and restore it to the robot in one press. Each backup is pictured from the best source available - the robot's own snapshot, or the saved map rendered exactly like the live map - and the `.bkmap` file itself is decoded to show the map's explored area, dock and room count. **Fetch from cloud** downloads your latest TP-Link backups without leaving the page.

## v0.22.0

### New

- **Map editor** on the sidebar page's new **Edit map** tab. Draw and delete no-go zones and virtual walls, and place furniture, directly on the live map, then save them to the robot with its own editing API - no cloud. Each change is held locally with undo until you press Save; the robot must be docked and idle to save. (Carpets and room names are drawn for context but are view-only for now.)
- **Restore a map backup to the robot** (`restore_map_backup`), fully locally. Home Assistant serves a backup it holds (from `fetch_cloud_map_backups`) on your LAN and the robot fetches and applies it with its own recovery - no app, no cloud round-trip. The robot must be able to reach Home Assistant directly on the LAN (a reverse proxy in front of HA breaks the robot's download, so the service uses HA's direct LAN address); `use_cloud_url: true` falls back to the backup's own TP-Link URL when the robot cannot reach HA. The robot must be docked and idle, and you pass `confirm: true`. Verified end to end: a change to the map was restored back to the backed-up state.

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


## v0.17.0

### New

- **Per-room "last cleaned"**: every finished run's map is folded onto the current map's rooms, so each room knows when it was last cleaned and what share of it the robot covered (runs that only crossed a room do not count). Kept across restarts; old records are backfilled a few per poll while the robot is docked. Exposed as `rooms_last_cleaned` and on each `room_geometry` entry of the map camera.
- **Card status panel**: the history button opens the last clean map, the recent runs (when, area, minutes, how started, preset) and consumable life bars. Holding a room shows its last-cleaned line.
- **Dashboard strategy** `custom:tapo-rv30`: one line of dashboard config builds a complete view per robot.
- The map camera carries `last_clean` (record details) and `last_clean_url`; the vacuum entity carries `consumables` (percent life left per part).


## v0.16.0

### New

- **Discovery**: Home Assistant offers the robot when it sees its DHCP lease (TP-Link MAC prefix E0:D3:62 so far; other prefixes welcome via an issue) and the robot answers on the TPAP port. An existing entry follows the robot when its IP changes.
- **Voice**: Assist sentences registered by the integration: "vacuum the kitchen and the lounge", "clean everywhere", "send the robot home", "stop the vacuum". Rooms resolve against the current map; the reply names anything it did not recognise.
- **Device triggers** for clean started / finished / error, so the events appear in the automation editor's device picker. Events now carry `device_id`.
- **Blueprints**: notify with the Last Clean Map when a run finishes; clean when everyone has left. Import badges in the README.
- **Icons**: the vacuum entity wears its own state-coloured robot picture; problem and charging binary sensors and every service get icons through icons.json. (Per-state sensor icons are not possible without renaming the sensor states, which would break automations, so those stay as they are.)
- **Furniture** on the map is now drawn as filled, anti-aliased illustrations (beds with pillows, sofas with cushions, tables with chairs, appliances, plants, toilet, pet items) instead of line glyphs.


## v0.15.0

### New

- **Furniture drawn on the map**: every item the app knows (beds, sofas, tables, TV cabinet, wardrobe, bedside table, fridge, washer, air conditioner, plants, toilet, pet house, litter box, pet bowl) gets its own glyph and label, rotated with the item. The glyphs are the integration's own drawings. Full type code table in the README.

### Changed

- Carpet Boost documented as the app's carpet cleaning preference (`setCarpetClean` boost / normal and `setCarpetAutoBoost` are the same setting on the RV30 Max Plus), so no separate select was added.


## v0.14.1

### Changed

- The Matter setup code is now its own **Matter Setup Code** sensor (diagnostic, off by default) instead of an attribute buried on the Matter sensor; the QR payload is its attribute.

## v0.14.0

### New

- **Matter**: a diagnostic sensor (off by default) with the robot's pairing state (`Not paired` / `Pairing window open` / `Paired`), paired ecosystems, time left in the pairing window, and the robot's fixed setup code and QR payload; an **Open Matter Pairing Window** button (`startCommission`); and `tapo_rv30.remove_matter_fabric`. Only created on robots that report the `matter` component. Status and setup-info reads verified on an RV30 Max Plus; the button and the remove service follow the app's code and are untested on hardware. See the README's Matter section, including why the code does not change but the window does.


## v0.13.0

### New

- **Last Clean Map** image entity: the newest clean record rendered from the robot's own copy (`getCleanRecordExtraInfo`): cleaned cells in blue, skipped rooms in grey, the driven path, start (green) and end (red) points, dock. Read once per record and only while the robot is not working. Record details (area, minutes, start type, map) are its attributes.
- **Schedules from Home Assistant**: `tapo_rv30.add_schedule`, `set_schedule` and `remove_schedule` drive the robot's own schedule list (`addScheduleRule` / `editScheduleRule` / `removeScheduleRules`, bodies verified on an RV30 Max Plus). Days accept Mon..Sun, daily, weekdays or weekend; rooms, a preset or the whole house; optional suction / water / passes. Repeating schedules only: in testing the robot stored a one-off rule on a different date than asked.


## v0.12.1

### Fixed

- `set_room_settings` on RV30 Max Plus firmware 1.3.3 failed with "Device error -1001": that firmware rejects the app's own per-room write, so it never worked there (it was listed as untested since 0.4). It now explains that and points at the alternatives.
- `clean_rooms` takes optional `suction`, `water` and `passes` for the run. The card's long-press room sheet now starts a clean of that room with the chosen levels instead of trying to save them.


## v0.12.0

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
