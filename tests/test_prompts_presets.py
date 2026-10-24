"""Status prompts and preset bodies (pure helpers)."""
import base64

from custom_components.tapo_rv30.mapdata import decode_prompt, new_prompts, preset_body
from custom_components.tapo_rv30.tpap import TapoVacuumClient


def test_decode_prompt_known_and_unknown():
    assert decode_prompt(11) == {"code": 11, "prompt": "dust_bag_full", "description": "Dust bag full"}
    assert decode_prompt(33)["prompt"] == "water_run_out"
    assert decode_prompt(99)["prompt"] == "unknown"
    assert decode_prompt("x")["prompt"] == "unknown"


def test_new_prompts_only_fires_for_new_instances():
    prev = {"prompts": [11], "prompt_ids": [1001]}
    assert new_prompts(prev, {"prompts": [11], "prompt_ids": [1001]}) == []        # still showing
    fired = new_prompts(prev, {"prompts": [11, 21], "prompt_ids": [1001, 1002]})
    assert [(p["prompt"], p["prompt_id"]) for p in fired] == [("area_unreachable", 1002)]
    again = new_prompts(prev, {"prompts": [11], "prompt_ids": [1005]})               # cleared and came back
    assert [p["prompt"] for p in again] == ["dust_bag_full"]


def test_new_prompts_without_ids_compares_codes():
    assert new_prompts({"prompts": [6]}, {"prompts": [6]}) == []
    assert [p["code"] for p in new_prompts({"prompts": [6]}, {"prompts": [6, 20]})] == [20]
    assert [p["code"] for p in new_prompts(None, {"prompts": [6]})] == [6]


def test_preset_body_matches_the_app():
    rooms = [{"id": 4, "suction": 2, "cistern": 2, "clean_number": 3},
             {"id": 5, "suction": 2, "cistern": 2, "clean_number": 3, "carpet_strategy": 1}]
    b = preset_body("All downstairs", 1792568378, rooms)
    assert base64.b64decode(b["rule_name"]).decode() == "All downstairs"
    assert b["mode"] == "room" and b["clean_order"] is True and "rule_id" not in b
    assert b["area_list"][0] == {"id": 4, "type": "room", "suction": 2, "cistern": 2, "clean_number": 3}
    assert b["area_list"][1]["carpet_strategy"] == 1
    assert preset_body("x", 1, rooms, rule_id=7)["rule_id"] == 7      # edit = same call with the id


def test_dock_actions_send_the_apps_switch_key():
    assert all(field == "switch" for _, _, field in TapoVacuumClient.DOCK_ACTIONS.values())
