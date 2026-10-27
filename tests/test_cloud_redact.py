"""A failed backup download must not hand back the presigned link: its query string is the key."""
import requests

from custom_components.tapo_rv30 import cloud

SIGNED = "https://store.example.com/maps/1.bin?X-Amz-Signature=abc123&X-Amz-Expires=600"


class _Cloud:
    def map_backups(self, thing):
        return [{"mapId": 1, "timestamp": 1700000000, "mapMd5": "x", "mapUrl": SIGNED}]

    def __init__(self, path_only=False):
        self.path_only = path_only

    def download(self, url):
        shown = url.split("example.com", 1)[1] if self.path_only else url     # urllib3 names the path only
        raise requests.ConnectionError(f"Max retries exceeded with url: {shown} (Caused by refused)")


def _error(tmp_path, monkeypatch, path_only):
    monkeypatch.setattr(cloud, "_connect", lambda *a: (_Cloud(path_only), {}))
    return cloud.fetch_backups(None, "u", "p", "t", str(tmp_path), local_reads=False)["backups"][0]["error"]


def test_a_failed_download_does_not_return_the_signed_link(tmp_path, monkeypatch):
    for path_only in (False, True):
        err = _error(tmp_path, monkeypatch, path_only)
        assert "X-Amz-Signature" not in err and "abc123" not in err
        assert "/maps/1.bin?<redacted> (Caused by refused)" in err


def test_plain_question_marks_are_left_alone(tmp_path, monkeypatch):
    class _Odd(_Cloud):
        def download(self, url):
            raise requests.ConnectionError("what? no")
    monkeypatch.setattr(cloud, "_connect", lambda *a: (_Odd(), {}))
    assert cloud.fetch_backups(None, "u", "p", "t", str(tmp_path), local_reads=False)["backups"][0]["error"] == "what? no"
