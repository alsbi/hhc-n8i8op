"""hhc-n8i8op Protocol Library — standalone, no Home Assistant dependency.

Pure async Python client for the hhc-n8i8op network relay board.

Supports:
  - Device discovery (AT+SEARCH / AT+READIP via UDP broadcast :65535)
  - Configuration read/write (binary TLV response format from Wireshark captures)
  - Relay control (TCP or UDP on port 5000)

All format details verified against real Tool.exe traffic captured in Wireshark.
See PROTOCOL.md for full specification.

Usage:

    # Discover a device
    config = await HHCClient.discover("192.168.0.105")

    # Read current config
    print(f"Name: {config.name}, Mode: {config.mode}, INMODE: {config.inmode}")

    # Change settings (READ → MODIFY → WRITE ALL pattern)
    config.inmode = 1   # Trigger mode
    ok = await client.write_config(config)

    # Control relays
    relay = HHCRelayClient("192.168.0.105", port=5000, protocol="tcp")
    await relay.on(1)        # channel 1 ON
    await relay.off(3)       # channel 3 OFF
    await relay.all_off()
    states = await relay.read()
"""

from __future__ import annotations

import asyncio
import logging
import socket
import struct
from dataclasses import dataclass

__all__ = [
    "HHCDeviceConfig",
    "HHCClient",
    "HHCRelayClient",
]

_LOGGER = logging.getLogger("hhc_protocol")

# ── Defaults ──────────────────────────────────────────────────────────────────

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


# ── Data structures ──────────────────────────────────────────────────────────


@dataclass
class HHCDeviceConfig:
    """Full device configuration from SEARCH/READIP response.

    Contains ALL fields that the device reports. When writing config back,
    we must send the COMPLETE set of AT+ commands as one binary payload
    to avoid partial writes that corrupt the device.

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
    mode: int | None = None  # AT+MODE: 0=TCP Server, 1=TCP Client, 2=UDP Service
    inmode: int | None = None  # AT+INMODE: 0=Unlinked, 1=Trigger, 2=Auto
    heartbeat: int | None = None  # AT+HEART — written as QUOTED string "0"
    mac: str | None = None  # AT+MAC — hex digits ONLY, no colons ("485300575500")
    name: str | None = None  # AT+NAME
    dhcp: int | None = None  # AT+DHCP: 0=static, 1=dhcp
    dns: str | None = None  # AT+DNSA
    mtcp: int | None = None  # AT+MTCP — raw byte: \x00 or \x01 (Wireshark-verified)
    message: str | None = None  # AT+MESSAGE
    ctime: int | None = None  # AT+CTIME — read as 2-byte BE uint16, written as QUOTED string "0"
    serialport_raw: bytes | None = None  # AT+SERIALPORT 4 raw bytes → val,val,val,val,
    status: int | None = None  # AT+STATUS — Power-off Preservation: 0=off, 1=on
    _raw_data: bytes | None = None  # Original TLV response (for debugging)
    _raw_tlv: dict | None = None  # Parsed TLV key→value pairs before field mapping

    def to_at_bytes(self, device_ip: str) -> bytes:
        """Build the FULL AT+ payload as raw bytes.

        Matches EXACTLY what Tool.exe sends over the wire (Wireshark-verified):
        one concatenated binary blob with all AT+ commands in order.

        Key format rules:
        - MAC without colons: "485300575500"
        - SERIALPORT: raw bytes with commas + trailing comma
          e.g. b'\\x05\\x2C\\x01\\x2C\\x00\\x2C\\x00\\x2C'
        - MTCP: raw byte \\x00 or \\x01, NO quotes
        - HEART/CTIME: QUOTED strings even for numeric values ("0")
        - MODE/DHCP/INMODE/STATUS: ASCII digits WITHOUT quotes
        - STATUS=0 or =1 only (single digit; =10 RESETS ALL RELAYS!)
        """
        parts: list[bytes] = []

        # 1. Device selector — which device to configure
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

        # 9. SERIALPORT — raw bytes with comma separators + trailing comma.
        # Wireshark-verified: Tool.exe sends b'\x05,\x01,\x00,\x00,'
        # (4 raw ComboBox indices, each followed by 0x2C comma, incl. trailing).
        # UDP uses length-based framing so \x00 bytes are fine.
        if self.serialport_raw is not None and len(self.serialport_raw) == 4:
            sp = bytearray()
            for i in range(4):
                sp.append(self.serialport_raw[i])
                sp.append(0x2C)  # comma after every byte (including trailing)
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

        # 14. HEART — ⚠️ QUOTED STRING! Not bare digit like MODE.
        hb_val = str(self.heartbeat) if self.heartbeat is not None else "0"
        parts.append(b'AT+HEART="' + hb_val.encode() + b'"')

        # 15. MTCP — RAW BYTE (0x00 or 0x01), NO quotes.
        # Wireshark-verified: Tool.exe sends AT+MTCP=\x00 (raw null byte).
        # UDP uses length-based framing — null bytes do NOT truncate the payload.
        if self.mtcp is not None:
            parts.append(b"AT+MTCP=" + bytes([self.mtcp & 0x01]))

        # 16. MESSAGE — quoted string
        msg_val = self.message if self.message is not None else ""
        parts.append(b'AT+MESSAGE="' + msg_val.encode() + b'"')

        # 17. CTIME — ⚠️ QUOTED STRING! Read as uint16 BE, write as string "N".
        ct_val = str(self.ctime) if self.ctime is not None else "0"
        parts.append(b'AT+CTIME="' + ct_val.encode() + b'"')

        # 18. INMODE — ASCII digit, NO quotes
        if self.inmode is not None:
            parts.append(b"AT+INMODE=" + str(self.inmode).encode())

        # 19. STATUS — Power-off Preservation
        # WARNING: AT+STATUS=10 RESETS ALL RELAYS! Always use single digit!
        status_digit = self.status if self.status is not None else 0
        parts.append(b"AT+STATUS=" + str(min(status_digit, 1)).encode())

        return b"".join(parts)


# ── TLV Parser ────────────────────────────────────────────────────────────────
#
# Format verified via Wireshark capture of real Tool.exe traffic:
#
#   IP fields:      KEYWORD + 4 raw bytes  (e.g. SEARCHIP + c0a80069)
#   Port fields:    KEYWORD + 2 bytes BE    (e.g. LOCALPORT + 1388)
#   MAC:            KEYWORD + 6 raw bytes   (e.g. MAC + 485300575500)
#   Byte fields:    KEYWORD + 1 byte         (e.g. MODE + 00)
#   String fields:  KEYWORD + len_byte + data (e.g. NAME + 0A + HHC-N8I8OP)
#   Raw4 fields:    KEYWORD + 4 raw bytes   (e.g. SERIALPORT + 05010000)

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
    """Parse device BINARY TLV response into {field_name: value} dict.

    Returns dict with human-readable values:
      IP/port/MAC/byte fields → Python types (str/int)
      SERIALPORT → hex string ("05010000")
      String fields → decoded ASCII strings
    """
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
                        # Device may include null terminator in length count;
                        # strip trailing \x00 to avoid corruption in AT+ commands.
                        raw = data[vs + 1 : vs + 1 + slen].decode(
                            "ascii", errors="replace"
                        ).rstrip("\x00")
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
    Individual field parse errors are logged and the field is left as None —
    the device may return corrupt/garbage data for some fields.
    """
    if len(data) < 24:
        _LOGGER.debug("Search response too short (%d bytes, need >=24)", len(data))
        return None

    # Reject ASCII command echoes (e.g. AT+READIP="172.16.10.16")
    # The real SEARCH response is binary TLV data that does NOT start with "AT+".
    if data.startswith(b"AT+"):
        _LOGGER.debug(
            "Response looks like ASCII AT-command echo (%d bytes), not binary TLV",
            len(data),
        )
        return None

    tlv = parse_tlv(data)
    if not tlv:
        _LOGGER.debug("Response did not parse as TLV: data=%s", data.hex())
        return None
    if "SEARCHIP" not in tlv and "IP" not in tlv:
        _LOGGER.debug("Parsed TLV missing IP field: keys=%s", list(tlv.keys()))
        return None

    cfg = HHCDeviceConfig()
    cfg._raw_data = data  # keep original bytes for debugging
    cfg._raw_tlv = dict(tlv)  # shallow copy of parsed key→value pairs

    cfg.ip = tlv.get("IP") or tlv.get("SEARCHIP")  # type: ignore[assignment]
    cfg.mask = tlv.get("SUBNET")  # type: ignore[assignment]
    cfg.gateway = tlv.get("GATEWAY")  # type: ignore[assignment]
    cfg.dest_ip = tlv.get("REMOTEIP")  # type: ignore[assignment]
    cfg.name = tlv.get("NAME")  # type: ignore[assignment]
    cfg.mac = tlv.get("MAC")  # type: ignore[assignment]  # without colons!

    # Numeric fields — wrap in try/except, device may return garbage
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
                    "Corrupt %s value in device response: %r — skipping",
                    tlv_key,
                    tlv[tlv_key],
                )

    cfg.dns = tlv.get("DNSA")  # type: ignore[assignment]
    cfg.message = tlv.get("MESSAGE")  # type: ignore[assignment]

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


# ── Internal UDP helpers ─────────────────────────────────────────────────────


class _FutureProtocol(asyncio.DatagramProtocol):
    """Base one-shot UDP protocol that resolves a Future."""

    def __init__(self, future: asyncio.Future) -> None:
        self._future = future

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # type: ignore[override]
        pass

    def error_received(self, exc: Exception) -> None:
        if not self._future.done():
            self._future.set_exception(
                exc if isinstance(exc, OSError) else OSError(exc)
            )

    def connection_lost(self, exc: Exception | None) -> None:  # type: ignore[override]
        if not self._future.done():
            self._future.set_exception(exc or OSError("Connection lost"))


class _BinaryResponseProtocol(_FutureProtocol):
    """Receives raw bytes (SEARCH/READIP responses)."""

    def datagram_received(self, data: bytes, addr: tuple[str | None, int]) -> None:
        if not self._future.done() and data and len(data) >= 24:
            self._future.set_result(data)


class _TextResponseProtocol(_FutureProtocol):
    """Receives ASCII text (AT+ SET/SAVE responses)."""

    def datagram_received(self, data: bytes, addr: tuple[str | None, int]) -> None:
        if not self._future.done():
            try:
                self._future.set_result(data.decode("ascii").strip())
            except UnicodeDecodeError as exc:
                self._future.set_exception(exc)


class _UDPRelayProtocol(asyncio.DatagramProtocol):
    """One-shot UDP protocol for relay commands on port 5000."""

    def __init__(self, message: bytes, future: asyncio.Future[str]) -> None:
        self._message = message
        self._future = future

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # type: ignore[override]
        transport.sendto(self._message)

    def datagram_received(self, data: bytes, addr: tuple[str | None, int]) -> None:
        if not self._future.done():
            try:
                self._future.set_result(data.decode("ascii").strip())
            except (UnicodeDecodeError, ValueError) as exc:
                self._future.set_exception(exc)

    def error_received(self, exc: Exception) -> None:
        if not self._future.done():
            self._future.set_exception(
                exc if isinstance(exc, OSError) else OSError(exc)
            )

    def connection_lost(self, exc: Exception | None) -> None:  # type: ignore[override]
        if not self._future.done():
            self._future.set_exception(exc or OSError("UDP connection lost"))


async def _open_broadcast_socket(
    source_port: int = AT_SOURCE_PORT,
) -> asyncio.DatagramTransport:
    """Open a UDP socket bound to :source_port with broadcast enabled."""
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: _FutureProtocol(loop.create_future()),
        local_addr=("0.0.0.0", source_port),
    )
    sock = transport.get_extra_info("socket")
    if sock is not None:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    return transport  # type: ignore[return-value]


# ── HHCClient: Discovery & Config ────────────────────────────────────────────


class HHCClient:
    """Async client for hhc-n8i8op discovery and configuration (AT commands).

    All communication uses UDP broadcast on port 65535.
    Source port MUST be 65535 (matches Tool.exe behavior, Wireshark-verified).
    """

    def __init__(self, host: str, *, timeout: float = DEFAULT_TIMEOUT) -> None:
        self.host = host
        self.timeout = timeout
        self._lock = asyncio.Lock()
        self._cached_config: HHCDeviceConfig | None = None
        self._udp_transport: asyncio.DatagramTransport | None = None

    async def shutdown(self) -> None:
        """Close UDP transport and release resources."""
        if self._udp_transport is not None:
            self._udp_transport.close()
            self._udp_transport = None

    @staticmethod
    async def discover(
        ip: str, *, timeout: float = DEFAULT_TIMEOUT
    ) -> HHCDeviceConfig | None:
        """Discover a specific device by IP address.

        Sends AT+SEARCH="N" + AT+READIP="<ip>" broadcasts.
        Retries up to 3 times with increasing delays.
        Returns parsed config on success, None if device didn't respond.
        """
        last_octet = ip.rsplit(".", maxsplit=1)[-1]
        search_payload = f'AT+SEARCH="{last_octet}"'.encode("ascii")
        readip_payload = f'AT+READIP="{ip}"'.encode("ascii")

        for attempt in range(3):
            loop = asyncio.get_running_loop()
            future: asyncio.Future[bytes] = loop.create_future()
            transport: asyncio.DatagramTransport | None = None

            try:
                transport, _ = await loop.create_datagram_endpoint(
                    lambda: _BinaryResponseProtocol(future),
                    local_addr=("0.0.0.0", AT_SOURCE_PORT),
                )
                sock = transport.get_extra_info("socket")
                if sock is not None:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

                bcast = "255.255.255.255"
                transport.sendto(search_payload, (bcast, AT_PORT))
                await asyncio.sleep(0.15)
                transport.sendto(readip_payload, (bcast, AT_PORT))
                await asyncio.sleep(0.15)
                transport.sendto(search_payload, (ip, AT_PORT))

                data = await asyncio.wait_for(future, timeout=timeout)
                cfg = parse_search_response(data)
                if cfg is not None:
                    return cfg
                # Got a response but it didn't parse — try next attempt
                _LOGGER.debug(
                    "Attempt %d: got %d bytes from %s but couldn't parse as TLV",
                    attempt + 1, len(data), ip,
                )

            except asyncio.TimeoutError:
                _LOGGER.debug("Attempt %d timed out for %s", attempt + 1, ip)
            except OSError as exc:
                _LOGGER.debug("Attempt %d failed for %s: %s", attempt + 1, ip, exc)
            finally:
                if transport is not None:
                    transport.close()

            # Longer pause between retries
            if attempt < 2:
                await asyncio.sleep(0.5)

        return None

    @staticmethod
    async def scan_subnet(
        *, timeout: float = DEFAULT_TIMEOUT
    ) -> list[tuple[str, HHCDeviceConfig]]:
        """Scan entire /24 subnet for devices (like Tool.exe Search button).

        Sends all 256 AT+SEARCH="N" packets in a burst, then collects responses.
        Prefer ``discover()`` when you already know the target IP.
        """
        results: list[tuple[str, HHCDeviceConfig]] = []
        loop = asyncio.get_running_loop()
        response_queue: list[bytes] = []
        transport: asyncio.DatagramTransport | None = None

        class _Collector(asyncio.DatagramProtocol):
            def connection_made(self, t: asyncio.DatagramTransport) -> None:  # type: ignore[override]
                pass

            def datagram_received(
                self, data: bytes, addr: tuple[str | None, int]
            ) -> None:
                if data and len(data) >= 10:
                    response_queue.append(data)

            def error_received(self, exc: Exception) -> None:
                _LOGGER.debug("Scan error: %s", exc)

            def connection_lost(self, exc: Exception | None) -> None:  # type: ignore[override]
                pass

        try:
            transport, _ = await loop.create_datagram_endpoint(
                _Collector,
                local_addr=("0.0.0.0", AT_SOURCE_PORT),
            )
            sock = transport.get_extra_info("socket")
            if sock is not None:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

            bcast = "255.255.255.255"
            for n in range(256):
                transport.sendto(f'AT+SEARCH="{n}"'.encode(), (bcast, AT_PORT))

            await asyncio.sleep(min(timeout, 3.0))

        except OSError as exc:
            _LOGGER.debug("Subnet scan failed: %s", exc)
            return results
        finally:
            if transport is not None:
                transport.close()

        seen_ips: set[str] = set()
        for raw in response_queue:
            cfg = parse_search_response(raw)
            if cfg is not None and cfg.ip is not None and cfg.ip not in seen_ips:
                seen_ips.add(cfg.ip)
                results.append((cfg.ip, cfg))

        _LOGGER.info("Subnet scan found %d device(s): %s", len(results), list(seen_ips))
        return results

    async def read_config(self) -> HHCDeviceConfig | None:
        """Read FULL current device configuration.

        This is the first step before ANY write operation.
        Stores result in cache for fallback during writes.
        """
        cfg = await self.discover(self.host, timeout=self.timeout)
        if cfg is not None:
            self._cached_config = cfg
        return cfg

    async def write_config(self, config: HHCDeviceConfig, *, save: bool = True) -> bool:
        """Write COMPLETE device config as one binary AT+ payload.

        IMPORTANT: This replaces the ENTIRE device configuration!
        Always call read_config() first, modify the returned object,
        then pass it here. This matches Tool.exe's READ→MODIFY→WRITE ALL pattern.

        Args:
            config: Full device config to write.
            save: If True, append AT+SAVE=1 (device reboots ~5 sec).

        Returns True if device responded "OK".
        """
        payload = config.to_at_bytes(self.host)
        if save:
            payload += b"AT+SAVE=1"

        result = await self._send_at(payload)
        if result is None:
            _LOGGER.warning("No response writing config to %s", self.host)
            return False

        ok = "OK" in result.upper()
        if ok:
            _LOGGER.info("Config written successfully to %s", self.host)
        else:
            _LOGGER.warning("Config write failed for %s: %s", self.host, result)
        return ok

    # ── Convenience methods (READ→MODIFY→WRITE ALL) ──

    async def set_input_mode(self, mode: int, *, save: bool = True) -> bool:
        """Set input mode: 0=Unlinked, 1=Trigger, 2=Auto."""
        config = await self._read_for_write()
        if config is None:
            return False
        config.inmode = mode
        return await self.write_config(config, save=save)

    async def set_work_mode(self, mode: int, *, save: bool = True) -> bool:
        """Set network work mode: 0=TCP Server, 1=TCP Client, 2=UDP Service."""
        config = await self._read_for_write()
        if config is None:
            return False
        config.mode = mode
        return await self.write_config(config, save=save)

    async def set_device_name(self, name: str, *, save: bool = True) -> bool:
        """Change device name."""
        config = await self._read_for_write()
        if config is None:
            return False
        config.name = name
        return await self.write_config(config, save=save)

    async def set_power_off_preservation(self, enabled: bool, *, save: bool = True) -> bool:
        """Set Power-off Preservation (AT+STATUS=1 or AT+STATUS=0).

        When enabled (1), relay states survive power cycles.
        When disabled (0), relays reset to off on power-up.

        ⚠️ AT+STATUS must be single ASCII digit '0' or '1' only.
        AT+STATUS=10 RESETS ALL RELAYS TO OFF!
        """
        config = await self._read_for_write()
        if config is None:
            return False
        config.status = 1 if enabled else 0
        return await self.write_config(config, save=save)

    async def set_network(
        self,
        *,
        ip: str | None = None,
        subnet: str | None = None,
        gateway: str | None = None,
        remote_ip: str | None = None,
        local_port: int | None = None,
        remote_port: int | None = None,
        dhcp: int | None = None,
        save: bool = True,
    ) -> bool:
        """Change network settings (IP, gateway, ports, etc.).

        Only the provided parameters are changed; others are preserved.
        ⚠️ Changing IP will make the device unreachable at the current address!
        After changing IP, create a new HHCClient with the new address.
        """
        config = await self._read_for_write()
        if config is None:
            return False
        if ip is not None:
            config.ip = ip
        if subnet is not None:
            config.mask = subnet
        if gateway is not None:
            config.gateway = gateway
        if remote_ip is not None:
            config.dest_ip = remote_ip
        if local_port is not None:
            config.local_port = local_port
        if remote_port is not None:
            config.dest_port = remote_port
        if dhcp is not None:
            config.dhcp = dhcp
        return await self.write_config(config, save=save)

    # ── Internals ──

    async def _read_for_write(self) -> HHCDeviceConfig | None:
        """Get device config for write operations.

        Tries fresh discovery first. Falls back to cached config
        from last successful read. Returns None only if we have NO config
        — in which case we MUST NOT write (would erase all settings).
        """
        config = await self.read_config()
        if config is not None:
            return config

        if self._cached_config is not None:
            _LOGGER.warning("Discovery timeout for %s — using cached config", self.host)
            return self._cached_config

        _LOGGER.error("Cannot write to %s — no config available", self.host)
        return None

    async def _send_at(self, payload: bytes) -> str | None:
        """Send raw bytes AT+ payload via UDP broadcast.

        Strategy:
          1. Try binding to source port 65535 (device expects this).
             Send to subnet broadcast + device unicast.
          2. If source port is taken, bind to random port and retry.
        Returns response text, or None on timeout.
        """
        bcast = ".".join(self.host.split(".")[:3] + ["255"])
        targets = [
            ("255.255.255.255", AT_PORT),  # global broadcast
            (bcast, AT_PORT),  # subnet broadcast
            (self.host, AT_PORT),  # direct unicast
        ]

        async with self._lock:
            for local_port in [AT_SOURCE_PORT, 0]:
                loop = asyncio.get_running_loop()
                future: asyncio.Future[str] = loop.create_future()
                transport: asyncio.DatagramTransport | None = None

                try:
                    # Bind to specific port first, fall back to random.
                    # No remote_addr → we control sendto destinations ourselves.
                    transport, _ = await loop.create_datagram_endpoint(
                        lambda: _TextResponseProtocol(future),
                        local_addr=("0.0.0.0", local_port),
                    )

                    sock = transport.get_extra_info("socket")
                    if sock is not None:
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

                    for addr in targets:
                        try:
                            transport.sendto(payload, addr)
                        except OSError:
                            pass  # some targets may be unreachable, that's fine

                    return await asyncio.wait_for(future, timeout=self.timeout)

                except asyncio.TimeoutError:
                    return None
                except OSError:
                    # Port 65535 already in use → try random port, log warning
                    if local_port == AT_SOURCE_PORT:
                        _LOGGER.warning(
                            "Cannot bind to source port %d, falling back to random port. "
                            "Discovery may be unreliable — ensure no other app uses port %d.",
                            AT_SOURCE_PORT,
                            AT_SOURCE_PORT,
                        )
                    continue
                finally:
                    if transport is not None and transport is not self._udp_transport:
                        transport.close()

            _LOGGER.warning("All AT send attempts failed for %s", self.host)
            return None


# ── HHCRelayClient: Relay Control ────────────────────────────────────────────


class HHCRelayClient:
    """Async client for hhc-n8i8op relay control on port 5000.

    Supports both TCP and UDP connections depending on device MODE setting.

    Commands:
        on1..on8     Turn relay channel ON
        off1..off8   Turn relay channel OFF
        allon        Turn ALL relays ON
        alloff       Turn ALL relays OFF
        read         Get relay states → "relayXXXXXXXX"
        input        Get input states → "inputXXXXXXXXXX"
    """

    def __init__(
        self,
        host: str,
        port: int = DEFAULT_DATA_PORT,
        protocol: str = "tcp",
        *,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = 3,
    ) -> None:
        self.host = host
        self.port = port
        self.protocol = protocol  # "tcp" or "udp"
        self.timeout = timeout
        self.retries = retries
        self._lock = asyncio.Lock()
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._connected = False

    async def shutdown(self) -> None:
        """Close persistent TCP connection and release resources."""
        await self._disconnect()

    async def _ensure_connection(self) -> None:
        """Open TCP connection if not already connected."""
        if self._connected and self._writer is not None:
            return
        self._reader, self._writer = await asyncio.wait_for(
            asyncio.open_connection(self.host, self.port),
            timeout=self.timeout,
        )
        self._connected = True

    async def _disconnect(self) -> None:
        """Close TCP connection gracefully."""
        if self._writer is not None:
            try:
                self._writer.close()
                await asyncio.wait_for(self._writer.wait_closed(), timeout=self.timeout)
            except (OSError, asyncio.TimeoutError):
                pass
            finally:
                self._writer = None
                self._reader = None
                self._connected = False

    # ── Public API ──

    async def send_command(self, command: str) -> str:
        """Send command with retry logic. Reconnects on dropped TCP connection."""
        async with self._lock:
            last_exc: Exception | None = None
            for attempt in range(1, self.retries + 1):
                try:
                    if self.protocol == "tcp":
                        return await self._send_tcp(command)
                    return await self._send_udp(command)
                except ConnectionResetError:
                    # TCP connection dropped — force reconnect on next attempt
                    self._connected = False
                    await self._disconnect()
                    last_exc = ConnectionResetError(
                        f"Connection to {self.host}:{self.port} reset"
                    )
                    if attempt < self.retries:
                        await asyncio.sleep(0.5 * attempt)
                except (
                    OSError,
                    TimeoutError,
                    asyncio.TimeoutError,
                    UnicodeDecodeError,
                ) as exc:
                    last_exc = exc
                    if attempt < self.retries:
                        await asyncio.sleep(0.5 * attempt)
            raise OSError(
                f"Command {command!r} failed after {self.retries} attempts"
            ) from last_exc

    async def on(self, channel: int) -> str:
        """Turn relay channel ON (1-based)."""
        return await self.send_command(f"on{channel}")

    async def off(self, channel: int) -> str:
        """Turn relay channel OFF (1-based)."""
        return await self.send_command(f"off{channel}")

    async def all_on(self) -> str:
        """Turn ALL relays ON."""
        return await self.send_command("allon")

    async def all_off(self) -> str:
        """Turn ALL relays OFF."""
        return await self.send_command("alloff")

    async def read(self) -> list[bool]:
        """Read relay states. Returns list[bool] where index 0 = channel 1."""
        raw = await self.send_command("read")
        return self.parse_relay_response(raw)

    async def read_inputs(self) -> list[bool]:
        """Read input states. Returns list[bool] where index 0 = input 1."""
        raw = await self.send_command("input")
        return self.parse_input_response(raw)

    @staticmethod
    def parse_relay_response(raw: str, channels: int = RELAY_CHANNELS) -> list[bool]:
        """Parse 'relayXXXXXXXX' → list of bool (index 0 = channel 1)."""
        if "relay" not in raw:
            raise ValueError(f"Invalid relay response: {raw!r}")
        bits_str = raw.split("relay", 1)[1]
        if len(bits_str) < channels:
            raise ValueError(
                f"Relay response too short: need {channels}, got {len(bits_str)}"
            )
        reversed_bits = bits_str[:channels][::-1]
        return [b == "1" for b in reversed_bits]

    @staticmethod
    def parse_input_response(raw: str, channels: int = RELAY_CHANNELS) -> list[bool]:
        """Parse 'inputXXXXXXXXXX' → list of bool (index 0 = input 1)."""
        if "input" not in raw:
            raise ValueError(f"Invalid input response: {raw!r}")
        bits_str = raw.split("input", 1)[1]
        reversed_bits = bits_str[:channels][::-1]
        return [b == "1" for b in reversed_bits]

    @staticmethod
    def parse_full_input_response(raw: str) -> list[bool]:
        """Parse 'inputXXXXXXXXXX' including global inputs (All On / All Off bits)."""
        if "input" not in raw:
            raise ValueError(f"Invalid input response: {raw!r}")
        bits_str = raw.split("input", 1)[1]
        return [b == "1" for b in bits_str[::-1]]

    # ── Transport internals ──

    async def _send_tcp(self, command: str) -> str:
        """Send command over persistent TCP and read response.

        Reuses open connection. Reads until newline or EOF.
        """
        await self._ensure_connection()
        assert self._writer is not None
        assert self._reader is not None

        self._writer.write(command.encode("ascii") + b"\n")
        await asyncio.wait_for(self._writer.drain(), timeout=self.timeout)

        data = await asyncio.wait_for(
            self._reader.readuntil(b"\n"), timeout=self.timeout
        )
        if not data:
            raise OSError("Empty TCP response")
        return data.decode("ascii").strip()

    async def _send_udp(self, command: str) -> str:
        loop = asyncio.get_running_loop()
        future: asyncio.Future[str] = loop.create_future()

        transport = None
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _UDPRelayProtocol(command.encode("ascii"), future),
                remote_addr=(self.host, self.port),
            )
            return await asyncio.wait_for(future, timeout=self.timeout)
        finally:
            if transport is not None:
                transport.close()


# ── CLI helpers ───────────────────────────────────────────────────────────────


def _main() -> None:
    """Quick CLI: python -m hhc_protocol <ip> [command].

    Without a command: discovers and prints device config.
    With a command: sends it to the relay (e.g. 'read', 'on1', 'off3').
    """
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m hhc_protocol <device_ip> [relay_command]")
        print("Examples:")
        print("  python -m hhc_protocol 192.168.0.105        # discover & show config")
        print("  python -m hhc_protocol 192.168.0.105 read   # read relay states")
        print("  python -m hhc_protocol 192.168.0.105 on1     # turn ch1 ON")
        sys.exit(1)

    ip = sys.argv[1]
    logging.basicConfig(
        level=logging.DEBUG, format="%(name)s %(levelname)s: %(message)s"
    )

    async def run() -> None:
        if len(sys.argv) >= 3:
            cmd = sys.argv[2]
            client = HHCRelayClient(ip)
            result = await client.send_command(cmd)
            print(result)
            if cmd == "read":
                states = HHCRelayClient.parse_relay_response(result)
                for i, on in enumerate(states, 1):
                    print(f"  CH{i}: {'ON' if on else 'OFF'}")
        else:
            config = await HHCClient.discover(ip)
            if config is None:
                print(f"Device at {ip} did not respond.")
                sys.exit(1)
            print(f"Device: {ip}")
            print(f"  Name:      {config.name}")
            print(f"  MAC:       {config.mac}")
            print(f"  IP:        {config.ip}")
            print(f"  Subnet:    {config.mask}")
            print(f"  Gateway:   {config.gateway}")
            print(f"  Remote IP: {config.dest_ip}")
            print(f"  Ports:     {config.local_port}/{config.dest_port}")
            mode_names = {0: "TCP Server", 1: "TCP Client", 2: "UDP Service"}
            print(f"  Work Mode: {config.mode} ({mode_names.get(config.mode, '?')})")
            inmode_names = {0: "Unlinked", 1: "Trigger", 2: "Auto"}
            print(
                f"  Input Mode:{config.inmode} ({inmode_names.get(config.inmode, '?')})"
            )
            print(f"  DHCP:      {config.dhcp}")
            print(f"  DNS:       {config.dns!r}")
            print(f"  Heartbeat: {config.heartbeat}")
            print(f"  MTCP:      {config.mtcp}")
            print(f"  Message:   {config.message!r}")
            print(
                f"  Serial:    {config.serialport_raw.hex() if config.serialport_raw else '?'}"
            )

    asyncio.run(run())


if __name__ == "__main__":
    _main()
