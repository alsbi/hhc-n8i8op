"""Internal UDP protocol helpers for hhc-n8i8op communication.

One-shot asyncio DatagramProtocol implementations used by
HHCClient (discovery/config) and HHCRelayClient (relay control).
"""

from __future__ import annotations

import asyncio
import socket
from typing import override

__all__ = [
    "_FutureProtocol",
    "_BinaryResponseProtocol",
    "_TextResponseProtocol",
    "_UDPRelayProtocol",
    "_open_broadcast_socket",
]


class _FutureProtocol(asyncio.DatagramProtocol):
    """Base one-shot UDP protocol that resolves a Future."""

    def __init__(self, future: asyncio.Future[bytes]) -> None:
        self._future: asyncio.Future[bytes] = future

    @override
    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        pass

    @override
    def error_received(self, exc: Exception) -> None:
        if not self._future.done():
            self._future.set_exception(
                exc if isinstance(exc, OSError) else OSError(exc)
            )

    @override
    def connection_lost(self, exc: Exception | None) -> None:
        if not self._future.done():
            self._future.set_exception(exc or OSError("Connection lost"))


class _BinaryResponseProtocol(_FutureProtocol):
    """Receives raw bytes (SEARCH/READIP responses).

    Accepts ANY non-empty packet (short packets are handled by the caller).
    """

    @override
    def datagram_received(self, data: bytes, addr: tuple[str | None, int]) -> None:
        if not self._future.done() and data:
            self._future.set_result(data)


class _TextResponseProtocol(_FutureProtocol):
    """Receives ASCII text (AT+ SET/SAVE responses).

    Internally stores Future[bytes] but resolves it with decoded ASCII text.
    This matches the original protocol design where set_result accepts bytes.
    """

    @override
    def datagram_received(self, data: bytes, addr: tuple[str | None, int]) -> None:
        if not self._future.done():
            try:
                # Store raw bytes; caller decodes to str
                self._future.set_result(data)
            except UnicodeDecodeError as exc:
                self._future.set_exception(exc)


class _UDPRelayProtocol(asyncio.DatagramProtocol):
    """One-shot UDP protocol for relay commands on port 5000."""

    def __init__(self, message: bytes, future: asyncio.Future[str]) -> None:
        self._message: bytes = message
        self._future: asyncio.Future[str] = future

    @override
    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        transport.sendto(self._message)

    @override
    def datagram_received(self, data: bytes, addr: tuple[str | None, int]) -> None:
        if not self._future.done():
            try:
                self._future.set_result(data.decode("ascii").strip())
            except (UnicodeDecodeError, ValueError) as exc:
                self._future.set_exception(exc)

    @override
    def error_received(self, exc: Exception) -> None:
        if not self._future.done():
            self._future.set_exception(
                exc if isinstance(exc, OSError) else OSError(exc)
            )

    @override
    def connection_lost(self, exc: Exception | None) -> None:
        if not self._future.done():
            self._future.set_exception(exc or OSError("UDP connection lost"))


async def _open_broadcast_socket(
    source_port: int,
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
