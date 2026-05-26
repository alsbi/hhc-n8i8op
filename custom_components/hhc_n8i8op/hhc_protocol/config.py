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
    "AT_RESPONSE_PORT",
    "AT_SOURCE_PORT",
    "DEFAULT_DATA_PORT",
    "DEFAULT_TIMEOUT",
    "RELAY_CHANNELS",
    "HHCDeviceConfig",
    "parse_search_response",
    "parse_tlv",
]

_LOGGER = logging.getLogger("hhc_protocol")

# ── Defaults ───────────────────────────────────────────────────────

AT_PORT: int = 65535
"""Destination port for AT+ commands (UDP)."""
AT_SOURCE_PORT: int = 65535
"""Source port for sending AT+ commands — MUST be 65535."""
AT_RESPONSE_PORT: int = 65534
"""Port where device sends responses (Chinese firmware quirk: replies to 65534)."""
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

    # ── to_at_bytes helpers (keep method cyclomatic complexity = A)

    def to_at_bytes(self, device_ip: str, *, include_save: bool = False) -> bytes:
        """Build FULL AT+ payload as raw bytes (Wireshark-verified).

        Key rules: MAC without colons; SERIALPORT uses raw commas;
        MTCP is ASCII digit '0'/'1' (NOT raw \x00 — it truncates payload!);
        HEART/CTIME are quoted strings;
        MODE/DHCP/INMODE/STATUS are unquoted digits;
        STATUS=0 or =1 only (=10 RESETS ALL RELAYS!).

        Args:
            device_ip: Target device IP for AT+SET selector.
            include_save: If True, appends AT+SAVE=1 which triggers device
                reboot (~5 seconds). Use with caution!
        """
        parts: list[bytes] = [b'AT+SET="' + device_ip.encode() + b'"']
        _append_quoted(parts, b"AT+IP=", self.ip)
        _append_quoted(parts, b"AT+SUBNET=", self.mask)
        _append_quoted(parts, b"AT+GATEWAY=", self.gateway)
        _append_quoted(parts, b"AT+REMOTEIP=", self.dest_ip)
        _append_quoted(parts, b"AT+MAC=", self.mac)
        _append_quoted(parts, b"AT+NAME=", self.name)
        _append_plain(parts, b"AT+MODE=", self.mode)
        _append_serialport(parts, self.serialport_raw)
        _append_quoted(parts, b"AT+LOCALPORT=", self.local_port)
        _append_quoted(parts, b"AT+REMOTEPORT=", self.dest_port)
        _append_plain(parts, b"AT+DHCP=", self.dhcp)
        _append_mandatory(parts, b'AT+DNSA="', self.dns or "")
        _append_mandatory(parts, b'AT+HEART="', str(self.heartbeat or 0))
        _append_mtcp(parts, self.mtcp)
        _append_mandatory(parts, b'AT+MESSAGE="', self.message or "")
        _append_mandatory(parts, b'AT+CTIME="', str(self.ctime or 0))
        _append_plain(parts, b"AT+INMODE=", self.inmode)
        parts.append(b"AT+STATUS=" + str(min(self.status or 0, 1)).encode())
        if include_save:
            parts.append(b"AT+SAVE=1")
        return b"".join(parts)


# ── AT+ serialization helpers (no branching in callers) ─────────────


def _append_quoted(parts: list[bytes], prefix: bytes, value: str | int | None) -> None:
    if value is not None:
        parts.append(prefix + b'"' + str(value).encode() + b'"')


def _append_plain(parts: list[bytes], prefix: bytes, value: int | None) -> None:
    if value is not None:
        parts.append(prefix + str(value).encode())


def _append_mandatory(parts: list[bytes], prefix: bytes, value: str) -> None:
    parts.append(prefix + value.encode() + b'"')


def _append_serialport(parts: list[bytes], raw: bytes | None) -> None:
    if raw is not None and len(raw) == 4:
        sp = bytearray()
        for i in range(4):
            sp.append(raw[i])
            sp.append(0x2C)
        parts.append(b"AT+SERIALPORT=" + bytes(sp))


def _append_mtcp(parts: list[bytes], value: int | None) -> None:
    if value is not None:
        parts.append(b"AT+MTCP=" + bytes([value & 0x01]))


# ── TLV definitions ───────────────────────────────────────────────────

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

# Map type → number of fixed bytes consumed (None = variable)
_TLV_FIXED_LEN: dict[str, int] = {
    "ip": 4,
    "port": 2,
    "uint16": 2,
    "mac": 6,
    "byte": 1,
    "raw4": 4,
}


# ── TLV value extractors ────────────────────────────────────────────


def _extract_ip(data: bytes, start: int) -> tuple[str, int]:
    return ".".join(str(b) for b in data[start : start + 4]), 4


def _extract_port(data: bytes, start: int) -> tuple[int, int]:
    return struct.unpack(">H", data[start : start + 2])[0], 2


def _extract_mac(data: bytes, start: int) -> tuple[str, int]:
    return data[start : start + 6].hex().upper(), 6


def _extract_byte(data: bytes, start: int) -> tuple[int, int]:
    return data[start], 1


def _extract_raw4(data: bytes, start: int) -> tuple[str, int]:
    return data[start : start + 4].hex(), 4


def _extract_string(data: bytes, start: int) -> tuple[str, int] | None:
    slen = data[start]
    end = start + 1 + slen
    if end > len(data):
        return None
    raw = data[start + 1 : end].decode("ascii", errors="replace").rstrip("\x00")
    return raw, 1 + slen


def _try_parse_tlv_field(
    kw: str, vtype: str, data: bytes, pos: int
) -> tuple[str | int, int] | None:
    """Try to parse one TLV field; return (value, consumed) or None."""
    kb = kw.encode("ascii")
    klen = len(kb)
    end_of_kw = pos + klen
    if end_of_kw > len(data) or data[pos:end_of_kw] != kb:
        return None
    vs = pos + klen
    if vs >= len(data):
        return None
    fix = _TLV_FIXED_LEN.get(vtype)
    result: tuple[str | int, int] | None = None
    if fix is not None:
        if vs + fix <= len(data):
            match vtype:
                case "ip":
                    result = (_extract_ip(data, vs)[0], klen + fix)
                case "port" | "uint16":
                    result = (_extract_port(data, vs)[0], klen + fix)
                case "mac":
                    result = (_extract_mac(data, vs)[0], klen + fix)
                case "byte":
                    result = (_extract_byte(data, vs)[0], klen + fix)
                case "raw4":
                    result = (_extract_raw4(data, vs)[0], klen + fix)
    elif vtype == "string":
        res = _extract_string(data, vs)
        if res is not None:
            val, step = res
            result = (val, klen + step)
    return result


def parse_tlv(data: bytes) -> dict[str, str | int]:
    """Parse device BINARY TLV response into {field_name: value} dict."""
    result: dict[str, str | int] = {}
    pos = 0
    while pos < len(data) - 2:
        matched = False
        for kw, vtype in _TLV_DEFS:
            parsed = _try_parse_tlv_field(kw, vtype, data, pos)
            if parsed is None:
                continue
            val, consumed = parsed
            result[kw] = val
            pos += consumed
            matched = True
            break
        if not matched:
            pos += 1
    return result


# ── parse_search_response helpers ───────────────────────────────────

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


def _fill_int_fields(cfg: HHCDeviceConfig, tlv: dict[str, str | int]) -> None:
    for tlv_key, attr_name in _SAFE_INT_FIELDS.items():
        if tlv_key not in tlv:
            continue
        try:
            setattr(cfg, attr_name, int(tlv[tlv_key]))
        except (ValueError, TypeError):
            _LOGGER.warning("Corrupt %s value: %r — skipping", tlv_key, tlv[tlv_key])


def _fill_serialport(cfg: HHCDeviceConfig, tlv: dict[str, str | int]) -> None:
    sp_val = tlv.get("SERIALPORT")
    if not isinstance(sp_val, str):
        return
    if len(sp_val) == 8:
        try:
            cfg.serialport_raw = bytes.fromhex(sp_val)
        except ValueError:
            _LOGGER.warning("Corrupt SERIALPORT hex value: %r — skipping", sp_val)
    else:
        _LOGGER.warning("Unexpected SERIALPORT length (%d): %r", len(sp_val), sp_val)


def _apply_tlv(cfg: HHCDeviceConfig, tlv: dict[str, str | int]) -> None:
    """Populate config from parsed TLV dict."""
    cfg.ip = cast("str | None", tlv.get("IP") or tlv.get("SEARCHIP"))
    cfg.mask = cast("str | None", tlv.get("SUBNET"))
    cfg.gateway = cast("str | None", tlv.get("GATEWAY"))
    cfg.dest_ip = cast("str | None", tlv.get("REMOTEIP"))
    cfg.name = cast("str | None", tlv.get("NAME"))
    cfg.mac = cast("str | None", tlv.get("MAC"))
    _fill_int_fields(cfg, tlv)
    cfg.dns = cast("str | None", tlv.get("DNSA"))
    cfg.message = cast("str | None", tlv.get("MESSAGE"))
    _fill_serialport(cfg, tlv)


def _validate_response(data: bytes, tlv: dict[str, str | int]) -> bool:
    if len(data) < 24:
        _LOGGER.debug("Search response too short (%d bytes, need >=24)", len(data))
        return False
    if data.startswith(b"AT+"):
        _LOGGER.debug("Response looks like ASCII AT-command echo, not binary TLV")
        return False
    if not tlv:
        _LOGGER.debug("Response did not parse as TLV: data=%s", data.hex())
        return False
    if "SEARCHIP" not in tlv and "IP" not in tlv:
        _LOGGER.debug("Parsed TLV missing IP field: keys=%s", list(tlv.keys()))
        return False
    return True


def parse_search_response(data: bytes) -> HHCDeviceConfig | None:
    """Parse SEARCH/READIP binary TLV response into HHCDeviceConfig.

    Returns None if the response cannot be parsed as valid TLV.
    Individual field parse errors are logged and the field left as None.
    """
    tlv = parse_tlv(data)
    if not _validate_response(data, tlv):
        return None

    cfg = HHCDeviceConfig()
    cfg._raw_data = data  # noqa: SLF001
    cfg._raw_tlv = dict(tlv)  # noqa: SLF001
    _apply_tlv(cfg, tlv)
    _LOGGER.debug(
        "Parsed TLV: ip=%s name=%s mode=%s inmode=%s mac=%s",
        cfg.ip,
        cfg.name,
        cfg.mode,
        cfg.inmode,
        cfg.mac,
    )
    return cfg
