# Tapo RV30 Robot Vacuum — Home Assistant Integration

Local-only Home Assistant integration for the **TP-Link Tapo RV30 Max Plus** robot vacuum.

Implements the **TPAP / SPAKE2+** authentication protocol reverse-engineered from
[python-kasa PR #1592](https://github.com/python-kasa/python-kasa/pull/1592).
No cloud dependency — communicates directly with the vacuum over your LAN.

## Features

- Full vacuum control — start, pause, stop, dock
- **Room-by-room cleaning** via `tapo_rv30.clean_rooms` service, or the native
  `vacuum.clean_area` action (map rooms to Home Assistant areas in the vacuum
  entity's settings; HA 2026.2+)
- **Current Room** sensor, inferred from the vacuum's position on the map
- **Schedules** sensor listing the Tapo-app schedules, and `tapo_rv30.run_schedule`
  to start one now
- Live colour **map image** rendered from LZ4 pixel data (refreshes every 5 min)
- Fan speed selection (Quiet / Standard / Turbo / Max / Ultra)
- Water level select (Off / Low / Medium / High)
- Clean passes select (1 / 2 / 3)
- Battery sensor
- Error state sensor (e.g. "Ok", "Dust Bin Removed", "Trapped")
- Consumable wear sensors (main brush, side brush, filter, sensor, charge contacts)
- Locate (beep) and spot clean
- Zone cleaning via `tapo_rv30.clean_zone` and per-room suction / water / passes via `tapo_rv30.set_room_settings`
- Empty Bin button and consumable reset buttons
- Auto Empty, Do Not Disturb (with start / end times), Child Lock and Carpet Boost switches
- Voice volume control
- Last Clean sensor with run totals
- Config flow UI — set up from Settings → Devices & Services

## Requirements

- Home Assistant 2025.1+ (2026.8+ needs v0.4.0 or later)
- [HACS](https://hacs.xyz) installed
- Tapo RV30 or RV20 on firmware **1.2.x+** (TPAP protocol)
- Python package `ecdsa` (installed automatically by HACS)

## Installation via HACS

[![Add to Home Assistant](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=epg-pers&repository=tapo-rv30-ha&category=integration)

Click the button above, or manually:

1. In HACS → **Integrations** → ⋮ menu → **Custom repositories**
2. Add `https://github.com/epg-pers/tapo-rv30-ha` as category **Integration**
3. Install **Tapo RV30 Robot Vacuum**
4. Restart Home Assistant
5. **Settings → Devices & Services → + Add Integration → Tapo RV30**
6. Enter your vacuum's IP address, Tapo account email, and password

## Services

| Service | What it does |
|---|---|
| `tapo_rv30.clean_rooms` | Clean named rooms (partial match). Optional `map`. |
| `tapo_rv30.clean_zone` | Clean rectangles given in map mm, same frame as the `position_mm` attribute. |
| `tapo_rv30.set_room_settings` | Per-room suction / water / passes. |
| `tapo_rv30.run_schedule` | Replay a saved schedule's rooms and settings now. The vacuum has no "run schedule by id" call, so the settings are re-sent and the clean started. |
| `tapo_rv30.send_raw` | Send any device method with params and get the response back (use with "Return response" in Developer Tools). Handy for diagnostics; writes change settings. |

Bad input (unknown room, map, option) raises an error with the available
names in it, so it shows in the UI and in automation traces.

## Dashboard

See [`jarvis_dashboard.yaml`](jarvis_dashboard.yaml) for a complete Lovelace dashboard.

Requires HACS frontend cards:
- [Mushroom](https://github.com/piitaya/lovelace-mushroom)
- [Xiaomi Vacuum Map Card](https://github.com/PiotrMachowski/lovelace-xiaomi-vacuum-map-card)

## Standalone CLI

[`tapo_vacuum.py`](tapo_vacuum.py) is a standalone command-line tool (no HA required):

```bash
pip install requests ecdsa lz4 Pillow
python3 tapo_vacuum.py status
python3 tapo_vacuum.py map
python3 tapo_vacuum.py clean kitchen lounge
```

## Supported Models

- **RV30 Max Plus (EU)** firmware 1.3.2
- **RV20 Max Plus (EU)** firmware 1.2.0

Should work on any Tapo RobovAC using TPAP.

## Protocol notes — room cleaning

The `setSwitchClean` payload for selective room cleaning was reverse-engineered
from live device traffic and, as far as we know, is not documented anywhere else.
Neither [python-kasa](https://github.com/python-kasa/python-kasa) (which only
implements whole-house `clean_mode: 0`) nor the official Home Assistant Tapo
integration implement room cleaning at the time of writing.

The correct payload is:

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

Key points:
- `clean_mode: 2` is **spot clean** — the `rooms` array is silently ignored
- `clean_mode: 3` is selective room clean
- `room_list` is a plain integer array of room IDs (the pixel values used in the LZ4 map)
- Discovered by reading `getSwitchClean` while the official Tapo app performed a room clean

## Credits

The TPAP / SPAKE2+ transport code (`custom_components/tapo_rv30/tpap.py` and
`tapo_vacuum.py`) is derived from the
[python-kasa](https://github.com/python-kasa/python-kasa) project
([PR #1592](https://github.com/python-kasa/python-kasa/pull/1592)), which is
licensed under GPL-3.0-or-later.

## License

This project is licensed under the GNU General Public License v3.0 or later.
See [`LICENSE`](LICENSE) for the full text.
