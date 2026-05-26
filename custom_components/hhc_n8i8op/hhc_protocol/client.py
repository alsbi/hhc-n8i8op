"""HHCClient — async client for hhc-n8i8op configuration (instance methods).

Static discovery methods (discover, scan_subnet, read_config_unicast, probe)
live in ._discovery to keep file size manageable.
"""

from __future__ import annotations

import asyncio
import logging
import socket as _socket

from .config import AT_PORT, AT_SOURCE_PORT, DEFAULT_TIMEOUT, HHCDeviceConfig
from ._discovery import discover, scan_subnet, read_config_unicast, probe
from ._udp_helpers import _TextResponseProtocol

__all__ = ["HHCClient"]

_LOGGER = logging.getLogger("hhc_protocol")


class HHCClient:
    """Async client for hhc-n8i8op discovery and configuration (AT commands)."""

    # Re-export static methods from _discovery module as class staticmethods
    discover = staticmethod(discover)
    scan_subnet = staticmethod(scan_subnet)
    read_config_unicast = staticmethod(read_config_unicast)
    probe = staticmethod(probe)

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

    async def read_config(self) -> HHCDeviceConfig | None:
        """Read FULL current device configuration.

        First step before ANY write operation.
        Stores result in cache for fallback during writes.
        """
        cfg = await self.discover(self.host, timeout=self.timeout)
        if cfg is not None:
            self._cached_config = cfg
        return cfg

    async def write_config(self, config: HHCDeviceConfig, *, save: bool = True) -> bool:
        """Write COMPLETE device config as one binary AT+ payload.

        IMPORTANT: Replaces ENTIRE device configuration!
        Always read_config() first, modify the returned object, then pass here.
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

    async def set_power_off_preservation(
        self, enabled: bool, *, save: bool = True
    ) -> bool:
        """Set Power-off Preservation. AT+STATUS must be single digit!"""
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
        """Change network settings. Only provided params are changed."""
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
        """Get config for write ops. Falls back to cache. None means MUST NOT write."""
        config = await self.read_config()
        if config is not None:
            return config
        if self._cached_config is not None:
            _LOGGER.warning("Discovery timeout for %s — using cached config", self.host)
            return self._cached_config
        _LOGGER.error("Cannot write to %s — no config available", self.host)
        return None

    async def _send_at(self, payload: bytes) -> str | None:
        """Send raw bytes AT+ payload via UDP broadcast. Returns response or None."""
        bcast = ".".join(self.host.split(".")[:3] + ["255"])
        targets = [
            ("255.255.255.255", AT_PORT),
            (bcast, AT_PORT),
            (self.host, AT_PORT),
        ]
        async with self._lock:
            for local_port in [AT_SOURCE_PORT, 0]:
                loop = asyncio.get_running_loop()
                future: asyncio.Future[bytes] = loop.create_future()
                transport: asyncio.DatagramTransport | None = None
                try:
                    transport, _ = await loop.create_datagram_endpoint(
                        lambda: _TextResponseProtocol(future),
                        local_addr=("0.0.0.0", local_port),
                    )
                    sock = transport.get_extra_info("socket")
                    if sock is not None:
                        sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_BROADCAST, 1)
                    for addr in targets:
                        try:
                            transport.sendto(payload, addr)
                        except OSError:
                            pass
                    data = await asyncio.wait_for(future, timeout=self.timeout)
                    return data.decode("ascii").strip()
                except asyncio.TimeoutError:
                    return None
                except OSError:
                    if local_port == AT_SOURCE_PORT:
                        _LOGGER.warning(
                            "Cannot bind to source port %d, falling back to random port.",
                            AT_SOURCE_PORT,
                        )
                    continue
                finally:
                    if transport is not None and transport is not self._udp_transport:
                        transport.close()
            _LOGGER.warning("All AT send attempts failed for %s", self.host)
            return None


# ── CLI helpers ───────────────────────────────────────────────────────────


def _main() -> None:
    """Quick CLI: python -m hhc_protocol <ip> [command]."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m hhc_protocol <device_ip> [relay_command]")
        sys.exit(1)
    ip_addr = sys.argv[1]
    logging.basicConfig(
        level=logging.DEBUG, format="%(name)s %(levelname)s: %(message)s"
    )

    async def run() -> None:
        if len(sys.argv) >= 3:
            cmd = sys.argv[2]
            from .relay import HHCRelayClient

            client = HHCRelayClient(ip_addr)
            result = await client.send_command(cmd)
            print(result)
            if cmd == "read":
                states = HHCRelayClient.parse_relay_response(result)
                for i, on_val in enumerate(states, 1):
                    print(f"  CH{i}: {'ON' if on_val else 'OFF'}")
        else:
            config = await HHCClient.discover(ip_addr)
            if config is None:
                print(f"Device at {ip_addr} did not respond.")
                sys.exit(1)
            mode_names = {0: "TCP Server", 1: "TCP Client", 2: "UDP Service"}
            inmode_names = {0: "Unlinked", 1: "Trigger", 2: "Auto"}
            print(f"Device: {ip_addr}")
            print(f"  Name:      {config.name}")
            print(f"  MAC:       {config.mac}")
            print(f"  IP:        {config.ip}")
            print(f"  Subnet:    {config.mask}")
            print(f"  Gateway:   {config.gateway}")
            print(f"  Remote IP: {config.dest_ip}")
            print(f"  Ports:     {config.local_port}/{config.dest_port}")
            print(
                f"  Work Mode: {config.mode} ({mode_names.get(config.mode or 0, '?')})"
            )
            print(
                f"  Input Mode:{config.inmode} ({inmode_names.get(config.inmode or 0, '?')})"
            )
            print(f"  DHCP:      {config.dhcp}")
            print(f"  DNS:       {config.dns!r}")
            print(f"  Heartbeat: {config.heartbeat}")
            print(f"  MTCP:      {config.mtcp}")
            print(f"  Message:   {config.message!r}")
            sp_hex = config.serialport_raw.hex() if config.serialport_raw else "?"
            print(f"  Serial:    {sp_hex}")

    asyncio.run(run())


if __name__ == "__main__":
    _main()
