# Tapo Robot Vacuum for Home Assistant

Local-only control of TP-Link Tapo robot vacuums (RV20, RV30 Max Plus, RV30C, RV50 and
relatives), with a live map card bundled in. No cloud, no extra downloads.

[Install with HACS](https://my.home-assistant.io/redirect/hacs_repository/?owner=epg-pers&repository=tapo-rv30-ha&category=integration){ .md-button .md-button--primary }
[Project README](https://github.com/epg-pers/tapo-rv30-ha#readme){ .md-button }

<p align="center">
  <img src="card.png" width="300" style="vertical-align: top; margin: 4px" alt="The bundled card, rooms mode">
  <img src="card-zones.png" width="300" style="vertical-align: top; margin: 4px" alt="The bundled card, zone mode">
  <img src="card-room.png" width="300" style="vertical-align: top; margin: 4px" alt="Room sheet with last cleaned">
</p>

*Mock-ups with a made-up house. The status panel with the last clean map, recent runs and
consumables is on the [entities](entities.md) page.*

## What is where

- [Entities](entities.md): everything the integration creates, by platform.
- [Services and events](services.md): every service with its fields, the events, and the
  Xiaomi map card calibration.
- [Matter](matter.md): pairing state, setup code, the pairing window and why the code does
  not change.
- [Protocol notes](protocol.md): what the robot answers locally, learned from live traffic
  and the Tapo app, including the warning about probing a working robot.
- [Troubleshooting](troubleshooting.md): symptoms, causes and fixes for the usual problems.

## Elsewhere

- [Changelog](https://github.com/epg-pers/tapo-rv30-ha/blob/main/CHANGELOG.md)
- [Contributing](https://github.com/epg-pers/tapo-rv30-ha/blob/main/CONTRIBUTING.md)
- [Issues](https://github.com/epg-pers/tapo-rv30-ha/issues)
