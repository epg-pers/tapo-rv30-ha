# Tapo RV30 Robot Vacuum — Home Assistant Integration

Local-only Home Assistant integration for the **TP-Link Tapo RV30 Max Plus** robot vacuum.

Implements the **TPAP / SPAKE2+** authentication protocol reverse-engineered from
[python-kasa PR #1592](https://github.com/python-kasa/python-kasa/pull/1592).
No cloud dependency — communicates directly with the vacuum over your LAN.

## Features

- Full vacuum control — start, pause, stop, dock
- **Room-by-room cleaning** via `tapo_rv30.clean_rooms` service
- Live colour **map image** rendered from LZ4 pixel data (refreshes every 5 min)
- Fan speed selection (Quiet / Standard / Turbo / Max / Ultra)
- Water level, clean passes
- Battery sensor
- Consumable wear sensors (main brush, side brush, filter, sensor, charge contacts)
- Config flow UI — set up from Settings → Devices & Services

## Requirements

- Home Assistant 2024.1+
- [HACS](https://hacs.xyz) installed
- Tapo RV30 on firmware **1.3.x+** (TPAP protocol)
- Python packages (installed automatically by HACS): `requests`, `ecdsa`, `lz4`, `Pillow`

## Installation via HACS

1. In HACS → **Integrations** → ⋮ menu → **Custom repositories**
2. Add `https://github.com/epg-pers/tapo-rv30-ha` as category **Integration**
3. Install **Tapo RV30 Robot Vacuum**
4. Restart Home Assistant
5. **Settings → Devices & Services → + Add Integration → Tapo RV30**
6. Enter your vacuum's IP address, Tapo account email, and password

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

Tested on **RV30 Max Plus (EU)** firmware 1.3.2. Should work on any Tapo RobovAC using TPAP.

## Credits

SPAKE2+ protocol implementation based on reverse engineering by the
[python-kasa](https://github.com/python-kasa/python-kasa) project.
