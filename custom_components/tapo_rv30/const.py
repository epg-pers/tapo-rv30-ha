"""Constants for Tapo RV30 integration."""
DOMAIN = "tapo_rv30"

CONF_HOST     = "host"
CONF_USERNAME = "username"
CONF_PASSWORD = "password"
CONF_PORT     = "port"
DEFAULT_PORT  = 4433

FAST_INTERVAL = 30   # seconds — status / battery / attrs
MAP_INTERVAL  = 300  # seconds — map image re-render

VACUUM_STATES = {
    0:   "idle",
    1:   "cleaning",
    2:   "cleaning",   # mapping counts as cleaning
    4:   "returning",
    5:   "docked",
    6:   "docked",
    7:   "paused",
    8:   "idle",
    100: "error",
}

FAN_SPEED_LIST = ["Quiet", "Standard", "Turbo", "Max", "Ultra"]
FAN_NAME_TO_INT = {n.lower(): i + 1 for i, n in enumerate(FAN_SPEED_LIST)}
FAN_INT_TO_NAME = {v: k.capitalize() for k, v in FAN_NAME_TO_INT.items()}

WATER_NAME_TO_INT = {"off": 0, "low": 1, "medium": 2, "high": 3}
WATER_INT_TO_NAME = {v: k for k, v in WATER_NAME_TO_INT.items()}

CONSUMABLE_LIMITS_H = {
    "roll_brush_time":     400,
    "edge_brush_time":     200,
    "filter_time":         200,
    "sensor_time":          30,
    "charge_contact_time":  30,
}
CONSUMABLE_LABELS = {
    "roll_brush_time":     "Main Brush",
    "edge_brush_time":     "Side Brush",
    "filter_time":         "Filter",
    "sensor_time":         "Sensor",
    "charge_contact_time": "Charge Contacts",
}

# Pastel room colours (R, G, B) — one per room slot
ROOM_PALETTE = [
    (255, 179, 186),  # pastel red
    (186, 225, 255),  # pastel blue
    (186, 255, 201),  # pastel green
    (255, 255, 186),  # pastel yellow
    (220, 186, 255),  # pastel purple
    (255, 220, 186),  # pastel orange
    (186, 255, 255),  # pastel cyan
]
WALL_COLOR    = (60,  60,  60)
UNKNOWN_COLOR = (210, 210, 210)
FLOOR_COLOR   = (240, 240, 240)
