# Getting started

Install from HACS, add the integration, and the robot is ready in the sidebar; nothing else to
install.

## What you need

- Home Assistant 2026.3 or newer (HACS enforces it) and [HACS](https://hacs.xyz/).
- A Tapo robot vacuum on your network, set up in the Tapo app with your own account. TPAP
  models need firmware 1.2 or newer; the older AES models (RV30C) are detected automatically,
  best effort.
- The email and password of the Tapo account that owns the robot. A shared account (one the
  owner shared the robot with) is refused by the robot itself; see
  [troubleshooting](troubleshooting.md#invalid-credentials-with-the-right-password).

## Install

1. Click the button below, or in HACS add `https://github.com/epg-pers/tapo-rv30-ha` as a
   custom repository of type Integration. Download it and restart Home Assistant.

    [Open in HACS](https://my.home-assistant.io/redirect/hacs_repository/?owner=epg-pers&repository=tapo-rv30-ha&category=integration){ .md-button .md-button--primary }

2. Home Assistant finds the robot on its own (it watches for the robot's network address) and
   offers "Tapo robot vacuum found". Enter your Tapo account email and password. If it is not
   offered: Settings, Devices and services, Add integration, **Tapo Robot Vacuum**, and type the
   robot's IP address.
3. Open **Tapo Vacuum** in the sidebar: map, schedules, history, rooms, drive, maintenance
   and settings. For your own dashboards, add a card and pick **Tapo Vacuum**
   ([the card](card.md)).

If the robot's IP address changes later, the entry follows it. A new password goes in through
the integration's **Reconfigure**, and Home Assistant asks for it by itself if the robot starts
refusing the stored one.

## Options

Settings, Devices and services, Tapo Robot Vacuum, **Configure**:

- **Show the Tapo Vacuum page in the sidebar**: on by default. Untick it if you only want the
  card and entities; it disappears immediately and comes back the same way.

The poll interval is a number entity on the device, so it can be changed without reloading.

## Updating and beta versions

HACS offers each new release. Bigger features land first as beta versions (for example
`0.18.0b1`): in HACS, open the integration, three-dot menu, **Redownload**, tick **Show beta
versions** and pick one. The [changelog](changelog.md) lists every release.

## Coming from a fork

Every fork of this project uses the same integration domain, so switching keeps your config
entry, entities, dashboards and automations. Steps in
[troubleshooting](troubleshooting.md#switching-from-a-fork).

## Supported models

| Model | Firmware | Status |
|---|---|---|
| RV30 Max Plus (EU) | 1.3.3 | Tested on every release, Home Assistant 2026.10 |
| RV20 Max Plus (EU) | 1.2.0 | Reported working |
| RV50 Pro Omni | unknown | Reported working on a fork; the Omni dock buttons here are untested |
| RV30C, RV30C Mop | unknown | AES transport, detected automatically, best effort ([#25](https://github.com/epg-pers/tapo-rv30-ha/issues/25)) |

Other Tapo RoboVac models should work with the features they report. Please open an issue with
your model and firmware either way; the templates ask for what helps.

## Two things to know

!!! warning "Firmware updates can break local access"
    Several users report that an RV30 Max (Plus) firmware update silently breaks local access
    on port 4433 (connection refused or a TLS handshake failure) until the robot is
    power-cycled. TP-Link's position is that third-party local access is unsupported. If
    polling stops after an update on an unchanged network, switch the robot off and on, and
    consider turning off the **Auto Firmware Update** switch. Thanks to @jan-tdy for documenting
    this.

!!! danger "Do not probe a robot while it is working"
    On 2026-10-21 an RV30 Max Plus was sent a batch of read-only setup and backup queries
    mid-run and, within seconds, aborted the run and lost its saved maps, clean history and
    cloud backups. The cause is not proven, but `tapo_rv30.send_raw` now refuses anything
    outside the integration's own methods while the robot is working. Details in the
    [protocol notes](protocol.md). Probe docked.
