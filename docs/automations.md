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
says what it did or which room it did not recognise. With more than one robot, say its name in
the sentence.

## Device triggers

In the automation editor, pick the robot as a device trigger: "started cleaning", "finished
cleaning" and "reported an error". They are the integration's events underneath; the event
data is listed under [services and events](services.md#events).

## Blueprints

| Blueprint | What it does | |
|---|---|---|
| Notify with the last clean map | Phone notification with area, minutes and the Last Clean Map image when a run finishes | [![Import](https://my.home-assistant.io/badges/blueprint_import.svg)](https://my.home-assistant.io/redirect/blueprint_import/?blueprint_url=https%3A%2F%2Fgithub.com%2Fepg-pers%2Ftapo-rv30-ha%2Fblob%2Fmain%2Fblueprints%2Fautomation%2Fepg-pers%2Fnotify_last_clean_map.yaml) |
| Clean when everyone has left | Start the house or chosen rooms once everyone has been away for a while, within a time window, only if docked | [![Import](https://my.home-assistant.io/badges/blueprint_import.svg)](https://my.home-assistant.io/redirect/blueprint_import/?blueprint_url=https%3A%2F%2Fgithub.com%2Fepg-pers%2Ftapo-rv30-ha%2Fblob%2Fmain%2Fblueprints%2Fautomation%2Fepg-pers%2Fclean_when_everyone_leaves.yaml) |

## Examples

[`examples/automations.yaml`](https://github.com/epg-pers/tapo-rv30-ha/blob/main/examples/automations.yaml)
has notifications from the events and a local weekday schedule.
[`tapo_vacuum.py`](https://github.com/epg-pers/tapo-rv30-ha/blob/main/tapo_vacuum.py) is a
standalone command-line tool that needs no Home Assistant.
