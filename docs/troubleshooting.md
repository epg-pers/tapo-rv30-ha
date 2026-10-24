# Troubleshooting

Symptoms first, then the cause and the fix. If yours is not here, open a bug report with the
template; it asks for the diagnostics download and the log lines that make the difference.

## The robot stops answering after a firmware update

**Symptom.** Everything worked, the robot updated itself, and now the integration logs
"connection refused" or a TLS handshake failure on port 4433 and the entities go
unavailable. A repair issue appears after ten minutes.

**Cause.** Some RV30 Max (Plus) firmware builds come up with the local API closed until the
robot is power-cycled. TP-Link's position is that third-party local access is unsupported.

**Fix.** Switch the robot off at its power switch, wait ten seconds, switch it on. Consider
turning off the Auto Firmware Update switch so updates happen when you choose.

## "Invalid credentials" with the right password

**Symptom.** The config flow says the credentials are invalid, but they work in the Tapo app.

**Cause.** The robot authenticates against the account that set it up. A shared account
(one the owner shared the robot with) is refused, and so is a Tapo ID with two-factor
authentication in some firmware versions. Email addresses are case sensitive on some
builds.

**Fix.** Use the owner's email and password, typed exactly as registered. If the owner
uses 2FA, try the password only (the local protocol does not use the second factor); if
that fails, report the model and firmware on issue #25.

## Asked to re-authenticate: "weaker security" or "pinned certificate"

**Symptom.** The integration asks you to re-authenticate, and the log says the robot "now
offers weaker security than when it was set up" or "no longer presents the pinned TP-Link
certificate".

**Cause.** At setup the integration remembers how the robot secures its local connection
(certificate mode, passcode types, device attestation). Discovery itself is not
authenticated, so a device answering in the robot's place could offer less; the integration
refuses rather than follow it. A factory reset, a new robot at the same address or some
firmware updates can change it legitimately.

**Fix.** If you reset or replaced the robot (or updated its firmware), re-authenticate from
the integration page: that stores what the robot offers now. If nothing changed on your side,
check that the address really is the robot before you do.

## "Device error -1002" in a service response

**Symptom.** A service or `send_raw` call answers "-1002".

**Cause.** The robot does not know that method. The method tables in the app cover several
models; each firmware implements a subset.

**Fix.** Nothing to fix. The integration only creates entities for what the robot answers;
if you were using `send_raw`, that method does not exist on your firmware. See
[protocol.md](protocol.md) for what the RV30 Max Plus answers.

## "Device error -1001" from set_room_settings

**Symptom.** Setting per-room suction, water or passes is refused.

**Cause.** RV30 Max Plus firmware 1.3.3 rejects the app's own per-room write; per-room
settings only exist inside presets there.

**Fix.** Give suction, water and passes to `tapo_rv30.clean_rooms` for the run, or make a
preset with `tapo_rv30.create_preset` (or in the Tapo app) and run it with
`tapo_rv30.run_preset`. Details in [protocol.md](protocol.md).

## Rooms stopped matching after a new map

**Symptom.** `vacuum.clean_area` cleans the wrong room or nothing after the robot built a
new map, or the card shows rooms but Home Assistant areas no longer map to them.

**Cause.** Room ids are per map. A new map (after a remap, or when the robot decides it is
on a new floor) renumbers them, and the area-to-room mapping in the vacuum entity's
settings still points at the old ids.

**Fix.** Open the vacuum entity's settings in Home Assistant and map the areas to the rooms
again. The card, `clean_rooms` and the voice sentences use names, so they follow the new
map on their own.

## The robot lost its maps

**Symptom.** The Tapo app shows a new, unnamed map, saved maps and backups are gone, and the
clean history starts from zero.

**Cause.** Not proven, but on 2026-10-21 an RV30 Max Plus was sent setup and backup queries
while it was mid-run and lost everything within seconds. The integration now refuses such
calls through `send_raw` while the robot is working.

**Fix.** Restore the map from a backup with `tapo_rv30.restore_map_backup`, then let the saved
map setup put back room names, zones, furniture, presets and schedules; the whole procedure is in
[map-recovery.md](map-recovery.md). Without a backup, remap and run `apply_map_setup`. Never
probe a working robot; see the warning in [protocol.md](protocol.md).

## The card does not appear in the card picker

**Symptom.** "Tapo Vacuum" is missing when adding a card, or the dashboard shows "Custom
element doesn't exist".

**Cause.** The card is registered as a dashboard resource at integration start. A browser
that loaded the dashboard before that keeps the old resource list; YAML-mode dashboards
get the card through an extra-module hook instead.

**Fix.** Reload the browser page (on the companion app, pull down to refresh or restart
the app). If it is still missing, Settings, Dashboards, Resources should list
`/tapo_rv30_static/tapo-rv30-card.js`; if it does not, restart Home Assistant once.

## Polling is slow or the map is stale

**Symptom.** Position and status lag by half a minute or more.

**Cause.** The idle poll interval defaults to 30 seconds; the robot is polled every 10
seconds only while cleaning or returning.

**Fix.** Lower the Poll Interval number entity. The map itself is re-rendered on a slower
cycle and immediately after map changes you make through the integration.

## Switching from a fork

Every fork of this project uses the same integration domain, `tapo_rv30`, so switching is
a swap, not a reinstall: in HACS remove the fork (keep the config entry when asked, or
simply do not delete the integration in Home Assistant), add
`https://github.com/epg-pers/tapo-rv30-ha` as a custom repository of type Integration,
download it and restart. Your config entry, entity ids, dashboards and automations carry
over. Entities the fork had and this project does not stay behind as "no longer provided":
delete them from the entity list. Entities new here appear. If the fork used a different domain, set the robot up again
here and remove the old entry afterwards.

## Still stuck

Download diagnostics (Settings, Devices and services, Tapo Robot Vacuum, three-dot menu),
turn on debug logging for `custom_components.tapo_rv30`, reproduce once, and open a bug
report with both. Credentials are redacted from diagnostics.
