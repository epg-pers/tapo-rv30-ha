"""Constants for Tapo RV30 integration."""
DOMAIN = "tapo_rv30"

CONF_HOST     = "host"
CONF_USERNAME = "username"
CONF_PASSWORD = "password"
CONF_PORT     = "port"
DEFAULT_PORT  = 4433

CONF_TRANSPORT = "transport"   # how to talk to the vacuum; picked in the config flow
TRANSPORT_TPAP = "tpap"        # SPAKE2+ (RV30 Max Plus, RV20 Max Plus on 1.2.x+)
TRANSPORT_AES  = "aes"         # python-kasa AES (RV30C, RV30C Mop, ...)

FAST_INTERVAL = 30   # seconds — status / battery / attrs (default; see CONF_POLL_INTERVAL)
MAP_INTERVAL  = 300  # seconds — full map re-render and settings re-read
CONF_POLL_INTERVAL = "poll_interval"   # entry option, seconds
MIN_POLL_INTERVAL  = 10
MAX_POLL_INTERVAL  = 300

# From the Tapo app's RobotStatusType enum (decompiled 2026-10-13).
# HA vacuum state per code; STATUS_LABELS is the human label for the Status sensor.
VACUUM_STATES = {
    0:  "idle",       # standby
    1:  "cleaning",
    2:  "cleaning",   # building map
    3:  "cleaning",   # remote control
    4:  "returning",
    5:  "docked",     # charging
    6:  "docked",     # charge done
    7:  "paused",
    8:  "idle",       # sleep
    9:  "docked",     # emptying dust (right after docking)
    10: "paused",     # map building paused
    11: "cleaning",   # going to point
    12: "paused",     # going to point paused
    13: "cleaning",   # exploring
    14: "paused",     # exploring paused
    15: "docked",     # washing mop
    16: "docked",     # drying mop
    17: "docked",     # attaching mop
    18: "docked",     # removing mop
    19: "docked",     # cutting hair
}
DOCKED_CODES = {c for c, s in VACUUM_STATES.items() if s == "docked"}
CLEANING_CODES = {c for c, s in VACUUM_STATES.items() if s == "cleaning"}
PAUSED_CODES   = {c for c, s in VACUUM_STATES.items() if s == "paused"}

STATUS_LABELS = {
    0: "Standby", 1: "Cleaning", 2: "Mapping", 3: "Remote Control",
    4: "Returning", 5: "Charging", 6: "Charged", 7: "Paused", 8: "Sleeping",
    9: "Emptying Dust", 10: "Mapping Paused", 11: "Going To Point",
    12: "Going To Point Paused", 13: "Exploring", 14: "Exploring Paused",
    15: "Washing Mop", 16: "Drying Mop", 17: "Attaching Mop",
    18: "Removing Mop", 19: "Cutting Hair",
}

FAN_SPEED_LIST = ["Quiet", "Standard", "Turbo", "Max", "Ultra"]
FAN_NAME_TO_INT = {n.lower(): i + 1 for i, n in enumerate(FAN_SPEED_LIST)}
FAN_INT_TO_NAME = {v: k.capitalize() for k, v in FAN_NAME_TO_INT.items()}

WATER_NAME_TO_INT = {"off": 0, "low": 1, "medium": 2, "high": 3}
WATER_INT_TO_NAME = {v: k for k, v in WATER_NAME_TO_INT.items()}

# From the Tapo app's RobotCleanErrorType enum (err_status codes).
ERROR_CODES = {
    0:  "Ok",
    1:  "Wheel Stuck",
    2:  "Side Brush Stuck",
    3:  "Main Brush Stuck",
    4:  "Lifted Off Floor",
    5:  "Bumper Stuck",
    6:  "Trapped",
    7:  "Cliff Sensor Blocked",
    8:  "Battery Error",
    9:  "Wheel Error",
    10: "Side Brush Motor Error",
    11: "Main Brush Motor Error",
    12: "Suction Fan Error",
    13: "Water Pump Error",
    14: "Dust Bin Removed",
    15: "Tilted",
    16: "Lidar Blocked",
    17: "Lidar Stuck Or Tangled",
    18: "Lidar Error",
    19: "Can't Locate (Cleaning)",
    20: "Can't Locate (Heading Home)",
    21: "Dock Not Found",
    22: "Low Battery, Recharging",
    23: "Lidar Cover Stuck",
    24: "No Dock, Stopped Returning",
    25: "Dust Bin Needs Cleaning",
    26: "Clean Water Tank Empty Or Missing",
    27: "Dirty Water Tank Full Or Missing",
    28: "Mop Auto-Install Failed",
    29: "Clean Tray Missing From Dock",
    30: "Clean Tray Overflow",
    31: "Mop Detached",
    32: "Mop Bracket Error",
    33: "Mopping Arm Error",
    34: "Mop Not Detected",
    35: "Fan Motor Blocked",
    36: "Mop Stuck",
    37: "Extending Mop Stuck",
    38: "Carpet Sensor Error",
    39: "Front Line Laser Error",
    40: "Side Line Laser Error",
    41: "Dirty Water Pump Error",
    42: "Drying Fan Error",
    43: "Drying Heater Error",
    44: "Dust Bag Not Installed",
    45: "Mop Install Failed",
}

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

# Map overlay colours (R, G, B[, A])
FORBID_COLOR       = (230, 60, 60, 90)    # no-go zone fill
FORBID_OUTLINE     = (200, 30, 30)
VIRTUAL_WALL_COLOR = (200, 30, 30)
CARPET_COLOR       = (205, 205, 205)
ZONE_OUTLINE       = (40, 110, 220)       # saved clean zone
FURNITURE_OUTLINE  = (120, 120, 120)

EVENT_CLEAN_STARTED  = "tapo_rv30_clean_started"
EVENT_CLEAN_FINISHED = "tapo_rv30_clean_finished"
EVENT_ERROR          = "tapo_rv30_error"
CONSUMABLE_WARN_FRACTION = 0.10   # "replace soon" below this fraction of life left

ACTIVE_POLL_INTERVAL = 10   # seconds while cleaning / returning (adaptive polling)
ISSUE_UNREACHABLE = "local_api_unreachable"
UNREACHABLE_AFTER = 600     # seconds of failed polls (after having worked) before raising the repair
