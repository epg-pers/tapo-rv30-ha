# Tapo Robot Vacuum for Home Assistant

Local-only control of TP-Link Tapo robot vacuums (RV20, RV30 Max Plus, RV30C, RV50 and
relatives), with a live map card bundled in. No cloud, no extra downloads. The `tapo_rv30`
domain name is historical; it is one integration for the range.

[![Add to Home Assistant](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=epg-pers&repository=tapo-rv30-ha&category=integration)

<p align="center">
  <img src="docs/card.png" width="340" alt="The bundled card, rooms mode">
  <img src="docs/card-zones.png" width="340" alt="The bundled card, zone mode">
</p>

*Mock-ups with a made-up house, rendered through the integration's own map code.*

## Quick start

1. Click the badge above, or in HACS add `https://github.com/epg-pers/tapo-rv30-ha` as a
   custom repository of type Integration. Download it and restart Home Assistant.
2. Home Assistant finds the robot on its own (it watches for its network address) and offers
   "Tapo robot vacuum found": enter your Tapo account email and password. If it is not
   offered, Settings, Devices and services, Add integration, **Tapo Robot Vacuum**, and type
   the robot's IP address. If the robot's IP changes later, the entry follows it. The robot must be on firmware 1.2 or
   newer (TPAP); the older AES models (RV30C) are detected automatically, best effort.
3. Add a card to a dashboard and pick **Tapo Vacuum**. Tap rooms to select them, drag a zone,
   long-press a room for levels, switch floors. Nothing else to install.

Needs Home Assistant 2026.3 or newer (HACS enforces it).

## Only here

- **Bundled map card**: tap-to-clean rooms through a lossless room mask (no calibration),
  zone drawing, saved zones, floors, presets, controls, theme-aware, visual editor
- **Live cleaning path** on the map, and a **Last Clean Map** of where the robot actually went
- **Schedules from Home Assistant**: add, change, enable / disable and remove the robot's own
- **Matter**: pairing state, setup code, and a button that opens the pairing window
- **Furniture** drawn as little illustrations on the map, from the app's own type table
- **Voice**: "vacuum the kitchen and the lounge" works in Assist with nothing to configure
- **Discovery**: the robot is found on the network and its entry follows IP changes
- Device triggers and blueprints for the automation editor; the vacuum wears its own
  state-coloured picture instead of a generic icon
- **Go to point**, per-run suction / water / passes, presets as buttons, native
  `vacuum.clean_area` with Home Assistant areas, events for start / finish / error
- Adaptive polling, hardened TPAP login, a repair issue when the robot stops answering,
  diagnostics, reconfigure and reauth from the integration page

## Voice

Assist understands the robot out of the box, no sentences to write:

- "vacuum the kitchen", "clean the lounge and the hallway", "hoover the dining room"
- "clean everywhere", "start the vacuum"
- "send the robot home", "tell the vacuum to dock"
- "stop the vacuum", "pause the robot"

Room names are matched against the robot's current map (partial matches work), and the reply
says what it did or which room it did not recognise. With more than one robot, say its name in
the sentence.

## Automations

Our events show up as device triggers in the automation editor ("Jarvis finished cleaning",
"Jarvis reported an error", "Jarvis started cleaning"), no raw event trigger needed. Two
ready-made blueprints:

| Blueprint | What it does | |
|---|---|---|
| Notify with the last clean map | Phone notification with area, minutes and the Last Clean Map image when a run finishes | [![Import](https://my.home-assistant.io/badges/blueprint_import.svg)](https://my.home-assistant.io/redirect/blueprint_import/?blueprint_url=https%3A%2F%2Fgithub.com%2Fepg-pers%2Ftapo-rv30-ha%2Fblob%2Fmain%2Fblueprints%2Fautomation%2Fepg-pers%2Fnotify_last_clean_map.yaml) |
| Clean when everyone has left | Start the house or chosen rooms once everyone has been away for a while, within a time window, only if docked | [![Import](https://my.home-assistant.io/badges/blueprint_import.svg)](https://my.home-assistant.io/redirect/blueprint_import/?blueprint_url=https%3A%2F%2Fgithub.com%2Fepg-pers%2Ftapo-rv30-ha%2Fblob%2Fmain%2Fblueprints%2Fautomation%2Fepg-pers%2Fclean_when_everyone_leaves.yaml) |

## Everything else

Sensors, switches, selects, numbers, buttons and the update entity adapt to what your model
reports. The full list is in [docs/entities.md](docs/entities.md), the services and events
in [docs/services.md](docs/services.md), Matter in [docs/matter.md](docs/matter.md), and the
local protocol, with what each call answers, in [docs/protocol.md](docs/protocol.md).

[`examples/dashboard.yaml`](examples/dashboard.yaml) is a ready-made view (controls, status
chips, the live map, presets, one-tap rooms, settings, maintenance; the chip rows use
[Mushroom](https://github.com/piitaya/lovelace-mushroom)) and
[`examples/automations.yaml`](examples/automations.yaml) covers notifications from the events
and a local weekday schedule. [`tapo_vacuum.py`](tapo_vacuum.py) is a standalone CLI that
needs no Home Assistant.

![Example dashboard](docs/dashboard.png)

## The card

```yaml
type: custom:tapo-rv30-card
entity: vacuum.robot
```

Options: `name`, `show_presets`, `show_controls`, `rotate` (0 / 90 / 180 / 270 for maps the
robot scanned sideways). Taps resolve through a room mask the integration serves, so
odd-shaped rooms work; a floor switcher appears when the robot has several maps; the header
shows status, current room, battery and progress, with a banner when the robot reports a
problem.

## Supported models

| Model | Firmware | Status |
|---|---|---|
| RV30 Max Plus (EU) | 1.3.3 | Tested on every release, Home Assistant 2026.10 |
| RV20 Max Plus (EU) | 1.2.0 | Reported working |
| RV50 Pro Omni | unknown | Reported working on a fork; the Omni dock buttons here are untested |
| RV30C, RV30C Mop | unknown | AES transport, detected automatically, best effort, see #25 |

Other Tapo RoboVac models should work with the features they report. Please open an issue
with your model and firmware either way; the bug and feature templates ask for what helps.

## Two things to know

**Firmware updates can break local access.** Several users report that an RV30 Max (Plus)
firmware update silently breaks local access on port 4433 (connection refused or TLS
handshake failure) until the robot is power-cycled; TP-Link's forum reply is that third-party
local access is unsupported. If polling stops after an update on an unchanged network, reboot
the vacuum and consider turning off automatic firmware updates in the Tapo app. Thanks to
@jan-tdy for documenting this.

**Do not probe a robot while it is working.** On 2026-10-21 an RV30 Max Plus was sent a
batch of read-only setup and backup queries mid-run and, within seconds, aborted the run and
lost its saved maps, clean history and cloud backups. The cause is not proven, but
`tapo_rv30.send_raw` now refuses anything outside the integration's own methods while the
robot is working, and the details are in [docs/protocol.md](docs/protocol.md). Probe docked.

## Contributing

Bug reports and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). Security
problems go through [SECURITY.md](SECURITY.md), not the issue tracker.

## Credits

The TPAP / SPAKE2+ transport code (`custom_components/tapo_rv30/tpap.py` and
`tapo_vacuum.py`) is derived from the
[python-kasa](https://github.com/python-kasa/python-kasa) project
([PR #1592](https://github.com/python-kasa/python-kasa/pull/1592)), which is
licensed under GPL-3.0-or-later.

Thanks to the people whose forks and PRs fed back in: @cheesyturkey (command fixes,
settings and dock entities), @jan-tdy (batching, retries, room geometry, schedules),
@peggleg (AES transport, schedules), @danieyal (TPAP hardening, charging sensor),
@Charles226 (security review), @cavefire (presets, capability discovery),
@ckarlof (map-card calibration), @G0LDENWASTAKEN (HA 2026.8 fix).

## License

This project is licensed under the GNU General Public License v3.0 or later.
See [`LICENSE`](LICENSE) for the full text.
