"""Map rename sends exactly what the Tapo app sends, and nothing that could save or delete a map."""
import base64

from custom_components.tapo_rv30 import tpap as T


def test_rename_payload_is_the_apps(tmp_path, monkeypatch):
    c = T.TapoVacuumClient("192.0.2.1", "u", "p", cache_dir=tmp_path)
    sent = []
    monkeypatch.setattr(c, "send", lambda m, p=None: sent.append((m, p)) or {"result": {}})
    c.rename_map(1792568378, "Küche")
    assert sent == [("setMapInfo", {"map_list": [{"map_id": 1792568378,
                                                  "map_name": base64.b64encode("Küche".encode()).decode()}]})]
    assert "is_base_exist" not in str(sent)
