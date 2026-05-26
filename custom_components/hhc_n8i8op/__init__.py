"""hhc-n8i8op integration — relay board control via TCP/UDP ASCII protocol."""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import ConfigEntry, ConfigEntryState
from homeassistant.const import CONF_HOST, CONF_PORT, Platform
from homeassistant.core import HomeAssistant, ServiceCall, SupportsResponse
from homeassistant.helpers import device_registry as dr

from .const import (
    DEVICE_MODE_LABELS,
    DEVICE_TO_INPUT_MODE,
    DOMAIN,
    INPUT_MODE_TO_DEVICE,
    INPUT_MODE_UNLINKED,
    OPT_INPUT_MODE,
    OPT_WORK_MODE,
    SERVICE_ALL_OFF,
    SERVICE_ALL_ON,
    SERVICE_READ_DEVICE_CONFIG,
    SERVICE_SET_INPUT_MODE,
    SERVICE_SET_WORK_MODE,
)
from .coordinator import HHCCoordinator

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [
    Platform.LIGHT,
    Platform.SWITCH,
    Platform.BUTTON,
    Platform.BINARY_SENSOR,
]


def _get_coordinators(hass: HomeAssistant, call: ServiceCall) -> list[HHCCoordinator]:
    """Return coordinators for the selected targets.

    If service call has device/entity targets, map them to coordinators.
    Otherwise fall back to all loaded coordinators.
    """
    coordinators: list[HHCCoordinator] = []

    target_device_ids: set[str] | None = None
    if call.target:
        target_device_ids = set()
        if "device_id" in call.target:
            target_device_ids.update(call.target["device_id"])
        if "entity_id" in call.target:
            entity_reg = dr.async_get(hass)
            for entity_id in call.target["entity_id"]:
                entity = entity_reg.async_get(entity_id)
                if entity and entity.device_id:
                    target_device_ids.add(entity.device_id)

    for entry in hass.config_entries.async_entries(DOMAIN):
        if entry.state is not ConfigEntryState.LOADED:
            continue
        coordinator = getattr(entry, "runtime_data", None)
        if not isinstance(coordinator, HHCCoordinator):
            continue

        if target_device_ids:
            device_reg = dr.async_get(hass)
            device = device_reg.async_get_device(
                identifiers={(DOMAIN, coordinator.device_id)}
            )
            if device is None or device.id not in target_device_ids:
                continue

        coordinators.append(coordinator)

    return coordinators


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up hhc-n8i8op from a config entry."""
    from .coordinator import HHCProtocolClient, HHCATClient
    from .const import CONF_PROTOCOL, DEFAULT_PORT

    host: str = entry.data[CONF_HOST]
    port: int = entry.data.get(CONF_PORT, DEFAULT_PORT)
    protocol: str = entry.data.get(CONF_PROTOCOL, "tcp")

    client = HHCProtocolClient(host, port, protocol)
    at_client = HHCATClient(host)
    coordinator = HHCCoordinator(hass, entry, client, at_client)

    entry.runtime_data = coordinator  # type: ignore[assignment]

    try:
        await coordinator.async_config_entry_first_refresh()
    except (TimeoutError, OSError):
        _LOGGER.warning("Initial refresh failed for %s — will retry on next poll cycle", host)

    # Read actual device state via SEARCH
    current_options = dict(entry.options)
    needs_update = False

    try:
        config = await coordinator.read_device_config()
        if config.inmode is not None:
            real_mode = DEVICE_TO_INPUT_MODE.get(config.inmode)
            if real_mode is not None:
                current_options[OPT_INPUT_MODE] = real_mode
                needs_update = True
        if config.mode is not None:
            current_options[OPT_WORK_MODE] = str(config.mode)
            needs_update = True
    except (TimeoutError, OSError):
        pass

    if needs_update:
        hass.config_entries.async_update_entry(entry, options=current_options)

    # Register services on first loaded entry
    _register_services(hass)

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    return True


def _register_services(hass: HomeAssistant) -> None:
    """Register domain services (idempotent)."""
    if hasattr(hass.data, f"{DOMAIN}_services_registered"):
        return

    hass.services.async_register(
        DOMAIN,
        SERVICE_SET_INPUT_MODE,
        _async_set_input_mode,
        schema=vol.Schema({
            vol.Required("mode"): vol.In(
                [INPUT_MODE_UNLINKED, "trigger", "auto"]
            ),
        }),
        supports_response=SupportsResponse.NONE,
    )

    hass.services.async_register(
        DOMAIN,
        SERVICE_SET_WORK_MODE,
        _async_set_work_mode,
        schema=vol.Schema({
            vol.Required("mode"): vol.All(int, vol.Range(min=0, max=2)),
        }),
        supports_response=SupportsResponse.NONE,
    )

    hass.services.async_register(
        DOMAIN,
        SERVICE_READ_DEVICE_CONFIG,
        _async_read_device_config,
        schema=vol.Schema({}),
        supports_response=SupportsResponse.ONLY,
    )

    hass.services.async_register(
        DOMAIN,
        SERVICE_ALL_ON,
        _async_all_on,
        schema=vol.Schema({}),
        supports_response=SupportsResponse.NONE,
    )

    hass.services.async_register(
        DOMAIN,
        SERVICE_ALL_OFF,
        _async_all_off,
        schema=vol.Schema({}),
        supports_response=SupportsResponse.NONE,
    )

    hass.data[f"{DOMAIN}_services_registered"] = True


async def _async_set_input_mode(call: ServiceCall) -> None:
    """Handle set_input_mode service."""
    mode_str: str = call.data["mode"]
    mode_val = INPUT_MODE_TO_DEVICE.get(mode_str, 1)

    for coordinator in _get_coordinators(call.hass, call):
        success = await coordinator.transition_mode(
            lambda mv=mode_val: coordinator.at_client.set_input_mode(mv),
        )
        if success:
            new_options = dict(coordinator.config_entry.options)
            new_options[OPT_INPUT_MODE] = mode_str
            call.hass.config_entries.async_update_entry(
                coordinator.config_entry, options=new_options
            )
        else:
            _LOGGER.error("Failed to set input mode on %s", coordinator.host)


async def _async_set_work_mode(call: ServiceCall) -> None:
    """Handle set_work_mode service."""
    mode: int = call.data["mode"]

    for coordinator in _get_coordinators(call.hass, call):
        success = await coordinator.transition_mode(
            lambda m=mode: coordinator.at_client.set_work_mode(m),
        )
        if success:
            new_options = dict(coordinator.config_entry.options)
            new_options[OPT_WORK_MODE] = str(mode)
            call.hass.config_entries.async_update_entry(
                coordinator.config_entry, options=new_options
            )
        else:
            _LOGGER.error("Failed to set work mode on %s", coordinator.host)


async def _async_read_device_config(call: ServiceCall) -> dict[str, Any]:
    """Handle read_device_config service."""
    results: dict[str, Any] = {}

    for coordinator in _get_coordinators(call.hass, call):
        config = await coordinator.read_device_config()

        result: dict[str, Any] = {
            "host": coordinator.host,
            "ip": config.ip,
            "mask": config.mask,
            "gateway": config.gateway,
            "dest_ip": config.dest_ip,
            "local_port": config.local_port,
            "dest_port": config.dest_port,
            "work_mode": f"{config.mode} ({DEVICE_MODE_LABELS.get(config.mode, 'unknown')})"
            if config.mode is not None else None,
            "input_mode": f"{config.inmode} ({DEVICE_TO_INPUT_MODE.get(config.inmode, 'unknown')})"
            if config.inmode is not None else None,
            "heartbeat": config.heartbeat,
            "mac": config.mac,
            "name": config.name,
        }

        results[coordinator.host] = result

    return results


async def _async_all_on(call: ServiceCall) -> None:
    """Turn all relays ON."""
    for coordinator in _get_coordinators(call.hass, call):
        await coordinator.set_all_on()


async def _async_all_off(call: ServiceCall) -> None:
    """Turn all relays OFF."""
    for coordinator in _get_coordinators(call.hass, call):
        await coordinator.set_all_off()


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry and shut down the coordinator."""
    coordinator: HHCCoordinator | None = entry.runtime_data  # type: ignore[assignment]
    if coordinator is not None:
        await coordinator.shutdown()
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)


async def async_remove_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Clean up after entry removal."""
    _LOGGER.debug("Removed config entry for %s", entry.data.get(CONF_HOST, "unknown"))
