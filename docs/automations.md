# Voice and automations

Assist understands the robot out of the box, the automation editor offers its events as device
triggers, and two blueprints cover the common jobs.

## Voice

No sentences to write:

- "vacuum the kitchen", "clean the lounge and the hallway", "hoover the dining room"
- "clean everywhere", "start the vacuum"
- "send the robot home", "tell the vacuum to dock"
- "stop the vacuum", "pause the robot"

Room names are matched against the robot's current map (partial matches work), and the reply
says what it did or which room it did not recognise. With more than one robot, say its name:
"tell Jarvis to clean the kitchen", "send Jarvis home", "stop Jarvis", or "vacuum the kitchen with
Jarvis". Without a name, the robot that has the rooms asked for (or, for stop, pause and home, the
one that is working) is used, and if that still leaves a choice Assist asks which robot.

## Device triggers

In the automation editor, pick the robot as a device trigger: "started cleaning", "finished
cleaning", "reported an error" and "gave a notice" (dust bag full, area unreachable and the
other robot notices). They are the integration's events underneath; the event
data is listed under [services and events](services.md#events).

## Blueprints

| Blueprint | What it does | |
|---|---|---|
| Notify with the last clean map | Phone notification with area, minutes and the Last Clean Map image when a run finishes | [![Import](https://my.home-assistant.io/badges/blueprint_import.svg)](https://my.home-assistant.io/redirect/blueprint_import/?blueprint_url=https%3A%2F%2Fgithub.com%2Fepg-pers%2Ftapo-rv30-ha%2Fblob%2Fmain%2Fblueprints%2Fautomation%2Fepg-pers%2Fnotify_last_clean_map.yaml) |
| Clean when everyone has left | Start the house or chosen rooms once everyone has been away for a while, within a time window, only if docked | [![Import](https://my.home-assistant.io/badges/blueprint_import.svg)](https://my.home-assistant.io/redirect/blueprint_import/?blueprint_url=https%3A%2F%2Fgithub.com%2Fepg-pers%2Ftapo-rv30-ha%2Fblob%2Fmain%2Fblueprints%2Fautomation%2Fepg-pers%2Fclean_when_everyone_leaves.yaml) |

The "Finished cleaning" trigger fires when the robot stops cleaning and heads home, before it
docks, often before it has logged the run. The Last Clean Map image is redrawn once the robot is
docked, so the notify blueprint waits (10 minutes at most) until the image shows this run's record:
the record in the event, or, when the event had none, a record newer than the one the image showed
when the event fired. If the image already shows it, the notification goes at once. The area,
minutes and any error come from the event's record, or from the image's attributes when the event
had none. If the image does not show this run in time, or Home Assistant restarted during the
run and the event had no record, the text is sent without a picture rather
than with the previous run's. Re-import the blueprint to pick this up; its inputs have not changed.

## Examples

[`examples/automations.yaml`](https://github.com/epg-pers/tapo-rv30-ha/blob/main/examples/automations.yaml)
has notifications from the events and a local weekday schedule.
[`tapo_vacuum.py`](https://github.com/epg-pers/tapo-rv30-ha/blob/main/tapo_vacuum.py) is a
standalone command-line tool that needs no Home Assistant.
