# Tapo Robot Vacuum for Home Assistant

Local-only control of TP-Link Tapo robot vacuums (RV20, RV30 Max Plus, RV30C, RV50 and
relatives), with a live map card bundled in. No cloud, no extra downloads.

[Install with HACS](https://my.home-assistant.io/redirect/hacs_repository/?owner=epg-pers&repository=tapo-rv30-ha&category=integration){ .md-button .md-button--primary }
[Get started](getting-started.md){ .md-button }

<p align="center">
  <img src="card.png" width="300" style="vertical-align: top; margin: 4px" alt="The bundled card, rooms mode">
  <img src="card-zones.png" width="300" style="vertical-align: top; margin: 4px" alt="The bundled card, zone mode">
  <img src="card-room.png" width="300" style="vertical-align: top; margin: 4px" alt="Room sheet with last cleaned">
</p>

*Mock-ups with a made-up house. More of the card, including the status panel and the go-to
tool, on [the card and dashboards](card.md).*

## What the Tapo app can't do

Everything the app does for day-to-day cleaning is here too. These are the things it has no way
to do at all:

- **Copy a map**, or restore a backup as a **new map** beside the original, so you can edit and
  try things on a copy and keep the map you rely on untouched (the app only restores over a map)
- **Keep your own map backups**: local copies of your cloud backups that survive TP-Link losing
  them, or the app deleting them along with a map, and restores served from your own network
- **Put a lost map back together**: restore it onto any map the robot has, and Home Assistant
  saves it under its old name and re-applies its room names, zones, furniture, presets and
  schedules from its saved setup
- **Clean map history**: every run's map kept for as long as you choose, long after the robot
  forgets the run, and downloadable
- **Per-room freshness**: when each room was last really cleaned, worked out from the robot's own
  run maps, for automations and the planner
- **Clean when it suits the house**: the planner keeps each room within a target like "every 2
  days", cleans when nobody is home and stays out of rooms whose motion sensors say they are in
  use
- **Home Assistant itself**: voice through Assist, rooms as Home Assistant areas, device
  triggers and events for automations, the last clean map in a phone notification, and several
  robots on one page
- **No cloud for control**: everything runs on your own network

## What is where

- [Getting started](getting-started.md): what you need, install, options, updates, supported
  models.
- [The planner](planner.md): keeps rooms clean by how long ago they were done, around
  the people and sensors in the house.
- [The sidebar page](panel.md): map, schedules editor, history with every run's map, rooms,
  drive, a map editor for any saved map, backups, maintenance, settings, and managing your maps
  (rename, turn, lock, preview, copy, delete).
- [The card and dashboards](card.md): card options, map modes, the one-line dashboard.
- [Voice and automations](automations.md): Assist sentences, device triggers, blueprints.
- [Entities](entities.md): everything the integration creates, by platform.
- [Services and events](services.md): every service with its fields, the events, and the
  Xiaomi map card calibration.
- [Matter](matter.md): pairing state, setup code, the pairing window and why the code does
  not change.
- [Map backup and recovery](map-recovery.md): restore a whole map backup to the robot locally,
  over its map or as a new one, copy a map, save and re-apply your no-go zones, walls, carpets
  and room names, and keep local copies of your cloud backups.
- [Protocol notes](protocol.md): what the robot answers locally, learned from live traffic
  and the Tapo app, including the warning about probing a working robot.
- [Troubleshooting](troubleshooting.md): symptoms, causes and fixes for the usual problems.

## Elsewhere

- [Changelog](changelog.md): every release, newest first.
- [Contributing](contributing.md): reporting bugs and working on the code.
- [Issues](https://github.com/epg-pers/tapo-rv30-ha/issues) and the
  [source](https://github.com/epg-pers/tapo-rv30-ha) on GitHub.
