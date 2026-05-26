"""Constants for the hhc-n8i8op integration."""

DOMAIN = "hhc_n8i8op"

# Config entry data keys (set once during setup)
CONF_HOST = "host"
CONF_PORT = "port"
CONF_PROTOCOL = "protocol"
CONF_CHANNEL_COUNT = "channel_count"

# Config entry options keys (changeable via OptionsFlow)
OPT_POLL_INTERVAL = "poll_interval"
OPT_CHANNEL_TYPES = "channel_types"
OPT_INPUT_MODE = "input_mode"  # how physical buttons behave (device-wide)
OPT_WORK_MODE = "work_mode"  # network protocol: 0=TCP Service, 2=UDP Service
OPT_DEVICE_NAME = "device_name"  # device name (AT+NAME)
OPT_POWER_OFF_PRESERVATION = "power_off_preservation"  # AT+STATUS: relay state survives power cycle

# Defaults
DEFAULT_PORT: int = 5000
DEFAULT_PROTOCOL: str = "tcp"
DEFAULT_CHANNEL_COUNT: int = 8
MAX_CHANNEL_COUNT: int = 8
DEFAULT_POLL_INTERVAL: float = 3
MIN_POLL_INTERVAL: float = 0.2
MAX_POLL_INTERVAL: float = 10

# Protocol constants (port 5000 — relay control)
SOCKET_TIMEOUT: float = 5.0
RETRY_COUNT: int = 3
RETRY_DELAY_BASE: float = 0.15

# AT-command configuration port (UDP broadcast, port 65535)
AT_PORT: int = 65535
AT_SOURCE_PORT: int = 65535  # source port for AT command packets — MUST be 65535
AT_SOCKET_TIMEOUT: float = 10.0

# ── Device work mode (AT+MODE=<N>) ──
# Full list from official Tool.exe:
#   0 = TCP Service  → device listens, HA connects and polls     ✅ works with HA
#   1 = TCP Client   → device connects outbound                 ❌ not usable
#   2 = UDP Service  → connectionless, HA sends/receives        ✅ works with HA
#   3 = UDP Client   → device sends outbound                    ❌ not usable
DEVICE_MODE_TCP_SERVICE: int = 0
DEVICE_MODE_UDP_SERVICE: int = 2

DEVICE_MODE_LABELS: dict[int, str] = {
    DEVICE_MODE_TCP_SERVICE: "TCP Service",
    DEVICE_MODE_UDP_SERVICE: "UDP Service",
}

# ── Input mode (AT+INMODE=<N>) ──
# Full list from official Tool.exe:
#   0 = Unlinked    → buttons decoupled from relays (do nothing)
#   1 = Trigger     → buttons directly toggle their matching relays
#   2 = Automatic   → auto-push input state on change (not useful for polling)
# INDEPENDENT of network work mode.  We only expose 0 and 1.
INPUT_MODE_UNLINKED: str = "unlinked"  # AT+INMODE=0
INPUT_MODE_TRIGGER: str = "trigger"  # AT+INMODE=1
INPUT_MODE_AUTO: str = "auto"  # AT+INMODE=2

INPUT_MODE_TO_DEVICE: dict[str, int] = {
    INPUT_MODE_UNLINKED: 0,
    INPUT_MODE_TRIGGER: 1,
    INPUT_MODE_AUTO: 2,
}

DEVICE_TO_INPUT_MODE: dict[int, str] = {v: k for k, v in INPUT_MODE_TO_DEVICE.items()}

# Sentinel: "don't change" value for dropdown selectors when
# the real device state is unknown. Prevents silent overwrite.
MODE_UNCHANGED: str = "_unchanged"

# Channel type values (for output entities in HA UI)
CHANNEL_TYPE_SWITCH: str = "switch"
CHANNEL_TYPE_LIGHT: str = "light"

# Global inputs — two extra physical inputs on the board:
GLOBAL_INPUT_ALL_ON: int = 0
GLOBAL_INPUT_ALL_OFF: int = 1
TOTAL_INPUT_EXTRA: int = 2

# Event type fired on input state change
EVENT_INPUT_CHANGED: str = f"{DOMAIN}_input_changed"

# Service names
SERVICE_SET_INPUT_MODE: str = "set_input_mode"  # AT+INMODE — button→relay coupling
SERVICE_SET_WORK_MODE: str = "set_work_mode"  # AT+MODE — network protocol
SERVICE_READ_DEVICE_CONFIG: str = "read_device_config"  # discovery SEARCH
SERVICE_ALL_ON: str = "all_on"
SERVICE_ALL_OFF: str = "all_off"
