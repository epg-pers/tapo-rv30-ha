"""Constants for Tapo RV30 integration."""
DOMAIN = "tapo_rv30"

CONF_HOST     = "host"
CONF_USERNAME = "username"
CONF_PASSWORD = "password"
CONF_PORT     = "port"
DEFAULT_PORT  = 4433

CONF_TRANSPORT = "transport"   # how to talk to the vacuum; picked in the config flow
CONF_SECURITY = "security"     # what the robot offered at setup (TPAP), so a downgrade is refused
CONF_MAC = "mac"               # the robot's MAC from discovery (TPAP), so another robot is refused
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
# Auto-empty frequency (dust_collection_mode in get/setDustCollectionInfo).
# directionControl direction codes (Tapo app, ButtonsWithoutDownControlView -> view model)
REMOTE_DIRECTIONS = {"forward": 0, "backward": 1, "left": 2, "right": 3, "stop": 4}
REMOTE_CONTROL_CODE = 3   # status while the robot is under remote control

AUTO_EMPTY_MODES = {0: "smart", 1: "light", 2: "balanced", 3: "max"}

# Furniture type codes as placed in the Tapo app (RobotFurnitureType in the app;
# 201 also confirmed on a real robot). Unknown codes are reported as their number.
FURNITURE_TYPES = {
    1: "Single bed", 2: "Double bed",
    101: "Single sofa", 102: "Double sofa", 103: "Sectional sofa",
    201: "Table and chairs", 202: "Square table", 203: "End table",
    301: "TV cabinet", 302: "Wardrobe", 303: "Bedside table",
    401: "Refrigerator", 402: "Front-load washer", 403: "Vertical air conditioner",
    503: "Green plants", 601: "Toilet",
    701: "Pet house", 702: "Cat litter box", 703: "Pet bowl",
}

EVENT_CLEAN_STARTED  = "tapo_rv30_clean_started"
EVENT_CLEAN_FINISHED = "tapo_rv30_clean_finished"
EVENT_ERROR          = "tapo_rv30_error"
EVENT_PROMPT         = "tapo_rv30_prompt"

# getVacStatus "prompt" codes: the robot's spoken/app notices. Names follow the app's
# RobotPromptType enum; 32 and 36 come from the firmware's event table.
PROMPT_CODES: dict[int, tuple[str, str]] = {
    1:  ("low_battery_start", "Battery too low to start"),
    2:  ("low_battery_start", "Battery too low to start"),
    3:  ("mop_installed", "Mop installed"),
    4:  ("mop_removed", "Mop removed"),
    5:  ("emptying_started", "Emptying the dustbin"),
    6:  ("clean_finished", "Cleaning finished"),
    7:  ("low_battery_recharging", "Low battery, returning to recharge"),
    8:  ("updating", "Updating firmware, cannot clean"),
    9:  ("charged_resuming", "Charged, resuming the clean"),
    10: ("charge_unknown", "Charging state unknown"),
    11: ("dust_bag_full", "Dust bag full"),
    12: ("dust_bag_missing", "Dust bag missing"),
    13: ("dust_duct_blocked", "Dust duct blocked"),
    14: ("emptying_too_often", "Emptying too often"),
    15: ("low_battery_shutdown", "Battery too low, shutting down"),
    16: ("update_failed", "Firmware update failed"),
    17: ("update_succeeded", "Firmware update succeeded"),
    18: ("returning_to_start", "Recharged, returning to where it stopped"),
    19: ("charging_stopped", "Charging stopped"),
    20: ("emptying_done", "Dustbin emptied"),
    21: ("area_unreachable", "Some of the area is unreachable"),
    22: ("rebuilding_map", "Could not relocate, building a new map"),
    23: ("started_in_no_go_zone", "Started inside a no-go zone"),
    30: ("stuck_too_long", "Stuck for too long"),
    31: ("paused_to_recharge", "Paused to recharge"),
    32: ("clean_charging_contacts", "Clean the charging contacts"),
    33: ("water_run_out", "Water tank empty"),
    36: ("dock_busy", "Dock busy"),
}
CONSUMABLE_WARN_FRACTION = 0.10   # "replace soon" below this fraction of life left

ACTIVE_POLL_INTERVAL = 10   # seconds while cleaning / returning (adaptive polling)
ISSUE_UNREACHABLE = "local_api_unreachable"
UNREACHABLE_AFTER = 600     # seconds of failed polls (after having worked) before raising the repair

# Integration options (options flow)
OPT_SHOW_PANEL = "show_panel"     # sidebar panel on / off (default on)
OPT_HISTORY_KEEP = "history_keep"     # how long clean maps are kept (cleanhistory.RETENTION_DAYS)
OPT_HISTORY_LIMIT = "history_limit"   # most clean maps kept
PANEL_URL_PATH = "tapo-vacuum"
