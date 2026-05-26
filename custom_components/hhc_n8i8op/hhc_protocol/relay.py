"""HHCRelayClient — async client for hhc-n8i8op relay control on port 5000.

Supports both TCP and UDP connections depending on device MODE setting.

Commands:
    on1..on8     Turn relay channel ON
    off1..off8   Turn relay channel OFF
    allon        Turn ALL relays ON
    alloff       Turn ALL relays OFF
    read         Get relay states → "relayXXXXXXXX"
    input        Get input states → "inputXXXXXXXXXX"
"""

from __future__ import annotations

import asyncio
import logging

from .config import DEFAULT_DATA_PORT, DEFAULT_TIMEOUT, RELAY_CHANNELS
from ._udp_helpers import _UDPRelayProtocol

__all__ = ["HHCRelayClient"]

_LOGGER = logging.getLogger("hhc_protocol")


class HHCRelayClient:
    """Async client for hhc-n8i8op relay control on port 5000.

    Supports both TCP and UDP connections depending on device MODE setting.
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

    # ── Parse methods ──

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
        """Send command over persistent TCP and read response."""
        await self._ensure_connection()
        assert self._writer is not None
        assert self._reader is not None

        self._writer.write(command.encode("ascii"))
        await asyncio.wait_for(self._writer.drain(), timeout=self.timeout)

        data = await asyncio.wait_for(
            self._reader.read(1024), timeout=self.timeout
        )
        if not data:
            raise OSError("Empty TCP response")
        return data.decode("ascii").strip()

    async def _send_udp(self, command: str) -> str:
        """Send command over UDP and wait for response."""
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
