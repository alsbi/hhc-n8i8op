"""hhc-n8i8op Protocol Library — re-exports public API.

Pure async Python client for the hhc-n8i8op network relay board.

Supports:
  - Device discovery (AT+SEARCH / AT+READIP via UDP broadcast :65535)
  - Configuration read/write (binary TLV response format from Wireshark captures)
  - Relay control (TCP or UDP on port 5000)

All format details verified against real Tool.exe traffic captured in Wireshark.
"""

from __future__ import annotations

from .config import (
    AT_PORT,
    AT_SOURCE_PORT,
    DEFAULT_DATA_PORT,
    DEFAULT_TIMEOUT,
    RELAY_CHANNELS,
    HHCDeviceConfig,
    parse_tlv,
    parse_search_response,
)
from .client import HHCClient
from .relay import HHCRelayClient

__all__ = [
    "AT_PORT",
    "AT_SOURCE_PORT",
    "DEFAULT_DATA_PORT",
    "DEFAULT_TIMEOUT",
    "RELAY_CHANNELS",
    "HHCClient",
    "HHCDeviceConfig",
    "HHCRelayClient",
    "parse_search_response",
    "parse_tlv",
]
