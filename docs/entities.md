# Entities

Everything is created per robot and adapts to what the model reports (`getComponentList`
plus a settings probe), so a feature the robot lacks simply has no entity.

## Vacuum

`vacuum.<name>` (shown with the integration's own state-coloured robot picture): start, pause, stop, return to base, locate, clean spot, fan speed
(Quiet / Standard / Turbo / Max / Ultra), and the native `vacuum.clean_area` action (map rooms
to Home Assistant areas in the entity's settings). Attributes: `fan_speed`, `water_level`,
`clean_passes`, `mop_attached`, `clean_area`, `clean_time_min`, `clean_percent`,
`position_mm`, `current_room`, `consumables` (percent life left per part), `prompts` (the
robot's active notices, for example `dust_bag_full`).

## Map

The map is what [the card](card.md) draws on; its modes and the status panel are described
there.

- `camera.<name>_map` and `image.<name>_map_image`: the live map as a transparent PNG with
  rooms, no-go zones, virtual walls, carpets, saved zones, furniture glyphs, the dock, the
  robot and its cleaning path. Attributes on the camera: `map_id`, `map_name`, `maps`,
  `rooms`, `room_geometry`, `map_geometry` (grid, mm to px transform, saved zones, furniture),
  `calibration_points`, `rooms_mask_url`, `path_points`, `rooms_last_cleaned` (per room: last cleaned
  timestamp and coverage percent, from the robot's own run maps), `last_clean`, `last_clean_url`.
- `image.<name>_last_clean_map`: the newest clean record rendered from the robot's own copy:
  cleaned cells, skipped rooms, path, start, end and dock. Attributes: area, minutes, start
  type, map name.

The vacuum's attributes include `rooms`, `position_mm`, `current_room`, `consumables` and the
capability flags `goto_point` and `remote_control`.

## Sensors

Status, Battery, Error, Last Clean Area, Clean Progress, Last Clean (with run totals), Total
Cleans, Total Area Cleaned, Total Cleaning Time, Current Room, Schedules (count, decoded list
as attributes, each with `blocked_by_dnd` when its time falls inside Do Not Disturb), consumable
life (Main Brush / Side Brush / Filter / Sensor / Charge Contacts Remaining, in percent) and use
(Main Brush Lid Used, Mop Cloth Used, in hours) for the parts the robot reports, Wi-Fi Signal (diagnostic, off by default), Matter and Matter Setup Code
(diagnostic, off by default; see [matter.md](matter.md)).

## Binary sensors

Charging, Problem (with code and text), Mop Attached, Do Not Disturb Active, and Replace
Soon per consumable the robot reports (on below 10% of service life).

## Switches

Auto Empty, Do Not Disturb, Auto Firmware Update, Child Lock, Carpet Boost (the app's carpet
cleaning preference), and on models that answer them: AI Obstacle Avoidance, Automatic
Re-mopping, Clean Along Floor, Extended Mopping, Pet Area Deep Clean, Sweep Walk.

## Selects

Water Level (Off / Low / Medium / High), Clean Passes (1 / 2 / 3), Auto Empty Mode (Smart /
Light / Balanced / Max, self-empty docks).

## Numbers and times

Voice Volume, Poll Interval, Do Not Disturb start and end.

## Buttons

Empty Bin (self-empty docks), Wash Mop / Dry Mop / Remove Hair (Omni docks, only when the
dock answers), one button per preset on the robot, consumable resets for the parts the robot reports
(including Mop Cloth), Open Matter
Pairing Window (diagnostic).

## Update

Firmware: read-only view of the robot's own update check. Installing is left to the app on
purpose, see the known firmware issue in the README.

## Repairs

A repair issue appears when a robot that used to answer has failed every poll for ten
minutes, pointing at the firmware regression and the fix (power-cycle).
