from custom_components.tapo_rv30.camera import _calibration_points


def test_calibration_points_round_trip():
    g = {"resolution_mm": 50, "real_origin_mm": [-5375, -1474], "grid_size": [174, 176], "scale_px_per_cell": 4}
    pts = _calibration_points(g)
    assert pts[0] == {"vacuum": {"x": -5375, "y": -1474}, "map": {"x": 2, "y": 702}}
    assert pts[1]["vacuum"]["x"] == -5375 + 173 * 50 and pts[1]["map"] == {"x": 694, "y": 702}
    assert pts[2]["vacuum"]["y"] == -1474 + 175 * 50 and pts[2]["map"] == {"x": 2, "y": 2}
    assert _calibration_points({}) is None
