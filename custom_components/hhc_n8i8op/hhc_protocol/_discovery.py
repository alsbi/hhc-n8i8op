"""Static discovery and probe methods for HHCClient.

Separated from client.py to keep file size under 300 lines.
These are standalone async functions attached to HHCClient as staticmethods.
"""

from __future__ import annotations

import asyncio
import logging
import re
import socket as _socket
from typing import override

from .config import (
    AT_PORT,
    AT_SOURCE_PORT,
    DEFAULT_TIMEOUT,
    HHCDeviceConfig,
    parse_search_response,
)
from ._udp_helpers import _BinaryResponseProtocol, _UDPRelayProtocol

__all__ = ["discover", "scan_subnet", "read_config_unicast", "probe"]

_LOGGER = logging.getLogger("hhc_protocol")
_RE_RELAY = re.compile(r"^relay[01]{8}$")


async def discover(
    ip: str, *, timeout: float = DEFAULT_TIMEOUT
) -> HHCDeviceConfig | None:
    """Discover a specific device by IP address.

    Sends AT+SEARCH="N" + AT+READIP="<ip>" broadcasts, retries up to 3 times.
    Returns parsed config on success, None if device didn't respond.
    """
    last_octet = ip.rsplit(".", maxsplit=1)[-1]
    search_payload = f'AT+SEARCH="{last_octet}"'.encode("ascii")
    readip_payload = f'AT+READIP="{ip}"'.encode("ascii")

    _LOGGER.info("Discovering device at %s (timeout=%.1fs)", ip, timeout)
    _LOGGER.debug(
        "Discovery payloads: SEARCH=%s READIP=%s", search_payload, readip_payload,
    )

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
                sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_BROADCAST, 1)

            bcast = "255.255.255.255"
            # Broadcast SEARCH + READIP, then unicast SEARCH to target IP
            transport.sendto(search_payload, (bcast, AT_PORT))
            await asyncio.sleep(0.15)
            transport.sendto(readip_payload, (bcast, AT_PORT))
            await asyncio.sleep(0.15)
            transport.sendto(search_payload, (ip, AT_PORT))
            _LOGGER.debug(
                "Attempt %d/3: sent SEARCH(bcast) + READIP(bcast) + SEARCH(%s)",
                attempt + 1, ip,
            )

            data = await asyncio.wait_for(future, timeout=timeout)
            cfg = parse_search_response(data)
            if cfg is not None:
                _LOGGER.info(
                    "Discovered %s: name=%s mac=%s mode=%s inmode=%s port=%s",
                    ip, cfg.name, cfg.mac, cfg.mode, cfg.inmode, cfg.local_port,
                )
                return cfg
            _LOGGER.warning(
                "Attempt %d/3 for %s: got %d bytes but not valid TLV response",
                attempt + 1, ip, len(data),
            )
        except asyncio.TimeoutError:
            _LOGGER.info(
                "Attempt %d/3 for %s timed out (%.1fs)",
                attempt + 1, ip, timeout,
            )
        except OSError as exc:
            _LOGGER.warning(
                "Attempt %d/3 for %s network error: %s",
                attempt + 1, ip, exc,
            )
        finally:
            if transport is not None:
                transport.close()
        if attempt < 2:
            await asyncio.sleep(0.5)

    _LOGGER.warning("Discovery failed after 3 attempts for %s", ip)
    return None


async def read_config_unicast(
    ip: str, *, timeout: float = DEFAULT_TIMEOUT
) -> HHCDeviceConfig | None:
    """Read device config by sending READIP unicast to specific IP.

    Unlike discover() which uses broadcast SEARCH+READIP,
    this sends a single unicast READIP packet directly to the device.
    Used when we already know the IP and need the full TLV config.
    """
    readip_payload = f'AT+READIP="{ip}"'.encode("ascii")
    _LOGGER.debug("Reading config via unicast READIP for %s", ip)
    loop = asyncio.get_running_loop()
    future: asyncio.Future[bytes] = loop.create_future()
    transport: asyncio.DatagramTransport | None = None
    try:
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _BinaryResponseProtocol(future),
            local_addr=("0.0.0.0", AT_SOURCE_PORT),
        )
        # Unicast — send direct to device IP, no broadcast needed
        transport.sendto(readip_payload, (ip, AT_PORT))
        data = await asyncio.wait_for(future, timeout=timeout)
        cfg = parse_search_response(data)
        if cfg is not None:
            _LOGGER.info("Unicast config read for %s: name=%s mac=%s", ip, cfg.name, cfg.mac)
            return cfg
        _LOGGER.warning(
            "Unicast READIP for %s: got %d bytes but not valid TLV", ip, len(data),
        )
    except asyncio.TimeoutError:
        _LOGGER.info("Unicast READIP timed out for %s (%.1fs)", ip, timeout)
    except OSError as exc:
        _LOGGER.warning("Unicast READIP failed for %s: %s", ip, exc)
    finally:
        if transport is not None:
            transport.close()
    return None


async def probe(ip: str, *, port: int = 5000, timeout: float = 5.0) -> str | None:
    """Auto-detect protocol (TCP vs UDP) on given port.

    Sends 'read\\n' simultaneously over TCP and UDP.
    First valid 'relayXXXXXXXX' response wins; on tie, prefer UDP.
    Returns "tcp", "udp", or None if no response.
    """

    async def _tcp_probe() -> str | None:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
            try:
                writer.write(b"read\n")
                await asyncio.wait_for(writer.drain(), timeout=timeout)
                data = await asyncio.wait_for(reader.readuntil(b"\n"), timeout=timeout)
                text = data.decode("ascii").strip()
                if _RE_RELAY.match(text):
                    _LOGGER.debug("TCP probe for %s: got '%s' → tcp", ip, text)
                    return "tcp"
                _LOGGER.debug("TCP probe for %s: unexpected response '%s'", ip, text)
            finally:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
                except (OSError, asyncio.TimeoutError):
                    pass
        except asyncio.TimeoutError:
            _LOGGER.debug("TCP probe for %s: connection timed out (%.1fs)", ip, timeout)
        except OSError as exc:
            _LOGGER.debug("TCP probe for %s: connection refused / network error: %s", ip, exc)
        except Exception as exc:
            _LOGGER.warning("TCP probe for %s: unexpected error: %s", ip, exc)
        return None

    async def _udp_probe() -> str | None:
        loop = asyncio.get_running_loop()
        future: asyncio.Future[str] = loop.create_future()
        transport = None
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _UDPRelayProtocol(b"read\n", future),
                remote_addr=(ip, port),
            )
            result = await asyncio.wait_for(future, timeout=timeout)
            if _RE_RELAY.match(result):
                _LOGGER.debug("UDP probe for %s: got '%s' → udp", ip, result)
                return "udp"
            _LOGGER.debug("UDP probe for %s: unexpected response '%s'", ip, result)
        except asyncio.TimeoutError:
            _LOGGER.debug("UDP probe for %s: timed out (%.1fs)", ip, timeout)
        except OSError as exc:
            _LOGGER.debug("UDP probe for %s: network error: %s", ip, exc)
        except Exception as exc:
            _LOGGER.warning("UDP probe for %s: unexpected error: %s", ip, exc)
        finally:
            if transport is not None:
                transport.close()
        return None

    tcp_task = asyncio.ensure_future(_tcp_probe())
    udp_task = asyncio.ensure_future(_udp_probe())
    tcp_result: str | None = None
    udp_result: str | None = None

    try:
        done, pending = await asyncio.wait(
            {tcp_task, udp_task}, timeout=timeout, return_when=asyncio.FIRST_COMPLETED
        )
        for task in done:
            try:
                result = task.result()
            except (asyncio.CancelledError, asyncio.TimeoutError):
                result = None
            except Exception as exc:
                _LOGGER.debug("Probe task exception: %s", exc)
                result = None
            if task is tcp_task:
                tcp_result = result
            elif task is udp_task:
                udp_result = result
        # Wait briefly for the other protocol to also respond
        remaining = pending
        if remaining:
            done2, pending2 = await asyncio.wait(
                remaining,
                timeout=min(timeout * 0.5, 2.0),
                return_when=asyncio.ALL_COMPLETED,
            )
            for task in done2:
                try:
                    result = task.result()
                except Exception:
                    result = None
                if task is tcp_task:
                    tcp_result = result
                elif task is udp_task:
                    udp_result = result
            for task in pending2:
                task.cancel()
    except Exception:
        tcp_task.cancel()
        udp_task.cancel()
        return None

    # Prefer UDP on tie (both respond) — more reliable for polling
    if udp_result == "udp":
        return "udp"
    if tcp_result == "tcp":
        return "tcp"
    return None


async def scan_subnet(
    *, timeout: float = DEFAULT_TIMEOUT
) -> list[tuple[str, HHCDeviceConfig]]:
    """Scan entire /24 subnet for devices (like Tool.exe Search button).

    Sends all 256 AT+SEARCH="N" packets in a burst, then collects responses.
    Short/unparseable responses accepted with sender address used as IP.
    """
    results: list[tuple[str, HHCDeviceConfig]] = []
    loop = asyncio.get_running_loop()
    response_queue: list[tuple[bytes, str]] = []
    transport: asyncio.DatagramTransport | None = None

    class _Collector(asyncio.DatagramProtocol):
        @override
        def connection_made(self, transport: asyncio.DatagramTransport) -> None:
            pass

        @override
        def datagram_received(self, data: bytes, addr: tuple[str | None, int]) -> None:
            if data and addr[0] is not None:
                response_queue.append((data, addr[0]))

        @override
        def error_received(self, exc: Exception) -> None:
            _LOGGER.debug("Scan error: %s", exc)

        @override
        def connection_lost(self, exc: Exception | None) -> None:
            pass

    try:
        transport, _ = await loop.create_datagram_endpoint(
            _Collector,
            local_addr=("0.0.0.0", AT_SOURCE_PORT),
        )
        sock = transport.get_extra_info("socket")
        if sock is not None:
            sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_BROADCAST, 1)
        bcast = "255.255.255.255"
        _LOGGER.info(
            "Scanning subnet via AT+SEARCH broadcast (256 packets to %s:%d, timeout=%.1fs)",
            bcast, AT_PORT, min(timeout, 3.0),
        )
        for n in range(256):
            transport.sendto(f'AT+SEARCH="{n}"'.encode(), (bcast, AT_PORT))
        await asyncio.sleep(min(timeout, 3.0))
    except OSError as exc:
        _LOGGER.warning("Subnet scan failed: %s", exc)
        return results
    finally:
        if transport is not None:
            transport.close()

    seen_ips: set[str] = set()
    for raw, sender_ip in response_queue:
        cfg = parse_search_response(raw)
        if cfg is not None and cfg.ip is not None and cfg.ip not in seen_ips:
            seen_ips.add(cfg.ip)
            results.append((cfg.ip, cfg))
        elif sender_ip not in seen_ips:
            _LOGGER.debug(
                "Scan: unparseable response from %s (%d bytes), adding as minimal device",
                sender_ip, len(raw),
            )
            minimal_cfg = HHCDeviceConfig(ip=sender_ip)
            seen_ips.add(sender_ip)
            results.append((sender_ip, minimal_cfg))

    if results:
        _LOGGER.info(
            "Subnet scan found %d device(s): %s",
            len(results),
            ", ".join(f"{ip} ({c.name or 'unnamed'})" for ip, c in results),
        )
    else:
        _LOGGER.info("Subnet scan found no devices")
    return results
