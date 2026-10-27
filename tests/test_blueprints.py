"""The shipped blueprints parse, and the clean-map notification waits for the map of this run."""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
BLUEPRINTS = ROOT / "blueprints" / "automation" / "epg-pers"


class _Input(str):
    """Home Assistant's !input tag, kept as the input's name."""


class _Loader(yaml.SafeLoader):
    pass


_Loader.add_constructor("!input", lambda loader, node: _Input(loader.construct_scalar(node)))


def _load(name: str) -> dict:
    return yaml.load((BLUEPRINTS / name).read_text(encoding="utf-8"), Loader=_Loader)


def test_every_blueprint_parses_and_uses_only_declared_inputs():
    files = sorted(BLUEPRINTS.glob("*.yaml"))
    assert files
    for path in files:
        bp = yaml.load(path.read_text(encoding="utf-8"), Loader=_Loader)
        declared = set(bp["blueprint"]["input"])
        used = set()

        def walk(node, used=used):
            if isinstance(node, _Input):
                used.add(str(node))
            elif isinstance(node, dict):
                for v in node.values():
                    walk(v)
            elif isinstance(node, list):
                for v in node:
                    walk(v)

        walk({k: v for k, v in bp.items() if k != "blueprint"})
        assert used <= declared, (path.name, used - declared)


def test_notify_inputs_unchanged():
    # Existing automations made from the blueprint must keep working after a re-import.
    bp = _load("notify_last_clean_map.yaml")
    assert set(bp["blueprint"]["input"]) == {"vacuum_device", "last_clean_image", "notify_service", "title"}
    assert bp["triggers"] == [{"trigger": "device", "domain": "tapo_rv30", "device_id": "vacuum_device",
                               "type": "clean_finished"}]


def test_notify_waits_for_this_runs_record_not_a_fixed_delay():
    bp = _load("notify_last_clean_map.yaml")
    actions = bp["actions"]
    assert not any("delay" in a for a in actions)
    vars_ = bp["variables"]
    # Captured when the event fires: the run's record, and the record the image showed then.
    assert "trigger.event.data.get('record')" in vars_["event_record"]
    assert "event_record.get('started')" in vars_["event_started"]
    assert vars_["shown_at_trigger"] == "{{ state_attr(last_clean_image, 'started') }}"
    wait = actions[0]
    tpl = wait["wait_template"]
    # Matched on the record, never on any redraw or a time window.
    assert "state_attr(last_clean_image, 'started')" in tpl
    assert "== event_started" in tpl
    assert "> shown_at_trigger" in tpl
    assert "states(" not in tpl and "- 60" not in tpl
    assert wait["timeout"] == {"minutes": 10}
    assert wait["continue_on_timeout"] is True


def test_notify_text_prefers_the_event_record_and_picture_only_when_matched():
    bp = _load("notify_last_clean_map.yaml")
    actions = bp["actions"]
    picked = actions[1]["variables"]
    # After a restart during the run (no record in the event, none shown at trigger) the next
    # redraw could be the previous run's: never matched, so text only.
    assert picked["fresh"] == ("{{ wait.completed and (event_started is not none"
                               " or shown_at_trigger is not none) }}")
    rec = picked["clean_record"]
    assert rec.index("if event_record") < rec.index("elif fresh")
    for attr in ("area", "minutes", "error"):
        assert f"state_attr(last_clean_image, '{attr}')" in rec
    notify = actions[2]
    assert notify["action"] == "notify_service"
    msg = notify["data"]["message"]
    assert "clean_record" in msg and "finished cleaning" in msg
    assert "if fresh else {}" in notify["data"]["data"]
    assert "/api/image_proxy/" in notify["data"]["data"]
