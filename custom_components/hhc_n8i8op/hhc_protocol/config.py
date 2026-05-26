"""HHC-N8I8OP device config dataclass and TLV parser.

Pure data — no I/O. Contains HHCDeviceConfig, parse_tlv(), parse_search_response(),
and protocol constants. All format details verified against Wireshark captures.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass
from typing import cast

__all__ = [
    "AT_PORT",
    "AT_SOURCE_PORT",
    "DEFAULT_DATA_PORT",
    "DEFAULT_TIMEOUT",
    "RELAY_CHANNELS",
    "HHCDeviceConfig",
    "parse_tlv",
    "parse_search_response",
]

_LOGGER = logging.getLogger("hhc_protocol")

# ── Defaults ───────────────────────────────────────────────────────

AT_PORT: int = 65535
"""Destination port for AT+ commands (UDP broadcast)."""
AT_SOURCE_PORT: int = 65535
"""Source port for AT+ commands — MUST be 65535 (verified via Wireshark)."""
DEFAULT_DATA_PORT: int = 5000
"""Default TCP/UDP data port for relay control."""
DEFAULT_TIMEOUT: float = 10.0
"""Default socket timeout in seconds."""
RELAY_CHANNELS: int = 8
"""Number of relay channels on the N8I8OP."""


@dataclass
class HHCDeviceConfig:
    """Full device configuration from SEARCH/READIP response.

    Field formats verified via Wireshark capture of Tool.exe traffic:
    - MAC stored WITHOUT colons ("485300575500") — matches AT+MAC= format
    - serialport_raw: raw bytes for AT+SERIALPORT=<binary>
    - mtcp: sent as single raw byte after '=' (not ASCII "0")
    """

    ip: str | None = None
    mask: str | None = None
    gateway: str | None = None
    dest_ip: str | None = None
    local_port: int | None = None
    dest_port: int | None = None
    mode: int | None = None  # 0=TCP Server, 1=TCP Client, 2=UDP Service
    inmode: int | None = None  # 0=Unlinked, 1=Trigger, 2=Auto
    heartbeat: int | None = None  # AT+HEART — written as QUOTED string "0"
    mac: str | None = None  # hex digits ONLY, no colons ("485300575500")
    name: str | None = None
    dhcp: int | None = None  # 0=static, 1=dhcp
    dns: str | None = None  # AT+DNSA
    mtcp: int | None = None  # raw byte: \x00 or \x01 (Wireshark-verified)
    message: str | None = None
    ctime: int | None = None  # read as 2-byte BE uint16, written as QUOTED string "0"
    serialport_raw: bytes | None = None  # 4 raw bytes → val,val,val,val,
    status: int | None = None  # Power-off Preservation: 0=off, 1=on
    _raw_data: bytes | None = None
    _raw_tlv: dict[str, object] | None = None

    def to_at_bytes(self, device_ip: str) -> bytes:
        """Build FULL AT+ payload as raw bytes (Wireshark-verified).

        Key rules: MAC without colons; SERIALPORT uses raw commas;
        MTCP is raw byte; HEART/CTIME are quoted strings;
        MODE/DHCP/INMODE/STATUS are unquoted digits;
        STATUS=0 or =1 only (=10 RESETS ALL RELAYS!).
        """
        parts: list[bytes] = []
        # 1. Device selector
        parts.append(b'AT+SET="' + device_ip.encode() + b'"')
        # 2-5. IP fields — dotted decimal, quoted
        if self.ip is not None:
            parts.append(b'AT+IP="' + self.ip.encode() + b'"')
        if self.mask is not None:
            parts.append(b'AT+SUBNET="' + self.mask.encode() + b'"')
        if self.gateway is not None:
            parts.append(b'AT+GATEWAY="' + self.gateway.encode() + b'"')
        if self.dest_ip is not None:
            parts.append(b'AT+REMOTEIP="' + self.dest_ip.encode() + b'"')
        # 6. MAC — hex digits only, NO colons, quoted
        if self.mac is not None:
            parts.append(b'AT+MAC="' + self.mac.encode() + b'"')
        # 7. Name — quoted string
        if self.name is not None:
            parts.append(b'AT+NAME="' + self.name.encode() + b'"')
        # 8. Mode — ASCII digit, NO quotes
        if self.mode is not None:
            parts.append(b"AT+MODE=" + str(self.mode).encode())
        # 9. SERIALPORT — raw bytes with comma separators + trailing comma
        if self.serialport_raw is not None and len(self.serialport_raw) == 4:
            sp = bytearray()
            for i in range(4):
                sp.append(self.serialport_raw[i])
                sp.append(0x2C)
            parts.append(b"AT+SERIALPORT=" + bytes(sp))
        # 10-11. Ports — decimal string, quoted
        if self.local_port is not None:
            parts.append(b'AT+LOCALPORT="' + str(self.local_port).encode() + b'"')
        if self.dest_port is not None:
            parts.append(b'AT+REMOTEPORT="' + str(self.dest_port).encode() + b'"')
        # 12. DHCP — ASCII digit, NO quotes
        if self.dhcp is not None:
            parts.append(b"AT+DHCP=" + str(self.dhcp).encode())
        # 13. DNSA — quoted string (may be empty "")
        dns_val = self.dns if self.dns is not None else ""
        parts.append(b'AT+DNSA="' + dns_val.encode() + b'"')
        # 14. HEART — QUOTED STRING!
        hb_val = str(self.heartbeat) if self.heartbeat is not None else "0"
        parts.append(b'AT+HEART="' + hb_val.encode() + b'"')
        # 15. MTCP — RAW BYTE, NO quotes
        if self.mtcp is not None:
            parts.append(b"AT+MTCP=" + bytes([self.mtcp & 0x01]))
        # 16. MESSAGE — quoted string
        msg_val = self.message if self.message is not None else ""
        parts.append(b'AT+MESSAGE="' + msg_val.encode() + b'"')
        # 17. CTIME — QUOTED STRING!
        ct_val = str(self.ctime) if self.ctime is not None else "0"
        parts.append(b'AT+CTIME="' + ct_val.encode() + b'"')
        # 18. INMODE — ASCII digit, NO quotes
        if self.inmode is not None:
            parts.append(b"AT+INMODE=" + str(self.inmode).encode())
        # 19. STATUS — single digit! =10 RESETS ALL RELAYS!
        status_digit = self.status if self.status is not None else 0
        parts.append(b"AT+STATUS=" + str(min(status_digit, 1)).encode())
        return b"".join(parts)


_TLV_DEFS: list[tuple[str, str]] = [
    # (keyword, value_type) — sorted by keyword length desc for greedy match
    ("REMOTEPORT", "port"),
    ("LOCALPORT", "port"),
    ("SERIALPORT", "raw4"),
    ("SEARCHIP", "ip"),
    ("REMOTEIP", "ip"),
    ("GATEWAY", "ip"),
    ("SUBNET", "ip"),
    ("MESSAGE", "string"),
    ("INMODE", "byte"),
    ("STATUS", "byte"),
    ("HEART", "byte"),
    ("CTIME", "uint16"),  # 2 bytes BE — NOT a string!
    ("MTCP", "byte"),
    ("DHCP", "byte"),
    ("DNSA", "string"),
    ("MODE", "byte"),
    ("NAME", "string"),
    ("BOOT", "string"),
    ("MAC", "mac"),
    ("APP", "string"),
    ("IP", "ip"),
]


def parse_tlv(data: bytes) -> dict[str, str | int]:
    """Parse device BINARY TLV response into {field_name: value} dict."""
    result: dict[str, str | int] = {}
    pos = 0
    while pos < len(data) - 2:
        matched = False
        for kw, vtype in _TLV_DEFS:
            kb = kw.encode("ascii")
            klen = len(kb)
            if pos + klen >= len(data):
                continue
            if data[pos : pos + klen] != kb:
                continue
            vs = pos + klen
            if vs >= len(data):
                break
            try:
                if vtype == "ip" and vs + 4 <= len(data):
                    result[kw] = ".".join(str(b) for b in data[vs : vs + 4])
                    pos = vs + 4
                elif vtype == "port" and vs + 2 <= len(data):
                    result[kw] = struct.unpack(">H", data[vs : vs + 2])[0]
                    pos = vs + 2
                elif vtype == "uint16" and vs + 2 <= len(data):
                    result[kw] = struct.unpack(">H", data[vs : vs + 2])[0]
                    pos = vs + 2
                elif vtype == "mac" and vs + 6 <= len(data):
                    result[kw] = data[vs : vs + 6].hex().upper()
                    pos = vs + 6
                elif vtype == "byte":
                    result[kw] = data[vs]
                    pos = vs + 1
                elif vtype == "raw4" and vs + 4 <= len(data):
                    result[kw] = data[vs : vs + 4].hex()
                    pos = vs + 4
                elif vtype == "string":
                    slen = data[vs]
                    if vs + 1 + slen <= len(data):
                        raw = (
                            data[vs + 1 : vs + 1 + slen]
                            .decode("ascii", errors="replace")
                            .rstrip("\x00")
                        )
                        result[kw] = raw
                        pos = vs + 1 + slen
                    else:
                        pos = vs + 1
                else:
                    pos += 1
                    continue
            except (struct.error, IndexError):
                pos += 1
                continue
            matched = True
            break
        if not matched:
            pos += 1
    return result


def parse_search_response(data: bytes) -> HHCDeviceConfig | None:
    """Parse SEARCH/READIP binary TLV response into HHCDeviceConfig.

    Returns None if the response cannot be parsed as valid TLV.
    Individual field parse errors are logged and the field left as None.
    """
    if len(data) < 24:
        _LOGGER.debug("Search response too short (%d bytes, need >=24)", len(data))
        return None
    if data.startswith(b"AT+"):
        _LOGGER.debug("Response looks like ASCII AT-command echo, not binary TLV")
        return None
    tlv = parse_tlv(data)
    if not tlv:
        _LOGGER.debug("Response did not parse as TLV: data=%s", data.hex())
        return None
    if "SEARCHIP" not in tlv and "IP" not in tlv:
        _LOGGER.debug("Parsed TLV missing IP field: keys=%s", list(tlv.keys()))
        return None

    cfg = HHCDeviceConfig()
    cfg._raw_data = data
    cfg._raw_tlv = dict(tlv)
    cfg.ip = cast("str | None", tlv.get("IP") or tlv.get("SEARCHIP"))
    cfg.mask = cast("str | None", tlv.get("SUBNET"))
    cfg.gateway = cast("str | None", tlv.get("GATEWAY"))
    cfg.dest_ip = cast("str | None", tlv.get("REMOTEIP"))
    cfg.name = cast("str | None", tlv.get("NAME"))
    cfg.mac = cast("str | None", tlv.get("MAC"))

    _SAFE_INT_FIELDS: dict[str, str] = {
        "LOCALPORT": "local_port",
        "REMOTEPORT": "dest_port",
        "MODE": "mode",
        "INMODE": "inmode",
        "HEART": "heartbeat",
        "DHCP": "dhcp",
        "MTCP": "mtcp",
        "CTIME": "ctime",
        "STATUS": "status",
    }
    for tlv_key, attr_name in _SAFE_INT_FIELDS.items():
        if tlv_key in tlv:
            try:
                setattr(cfg, attr_name, int(tlv[tlv_key]))
            except (ValueError, TypeError):
                _LOGGER.warning(
                    "Corrupt %s value: %r — skipping", tlv_key, tlv[tlv_key]
                )

    cfg.dns = cast("str | None", tlv.get("DNSA"))
    cfg.message = cast("str | None", tlv.get("MESSAGE"))

    sp_val = tlv.get("SERIALPORT")
    if isinstance(sp_val, str):
        try:
            if len(sp_val) == 8:
                cfg.serialport_raw = bytes.fromhex(sp_val)
            else:
                _LOGGER.warning(
                    "Unexpected SERIALPORT length (%d): %r", len(sp_val), sp_val
                )
        except ValueError:
            _LOGGER.warning("Corrupt SERIALPORT hex value: %r — skipping", sp_val)

    _LOGGER.debug(
        "Parsed TLV: ip=%s name=%s mode=%s inmode=%s mac=%s",
        cfg.ip,
        cfg.name,
        cfg.mode,
        cfg.inmode,
        cfg.mac,
    )
    return cfg
