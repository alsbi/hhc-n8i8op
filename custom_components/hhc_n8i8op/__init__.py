"""hhc-n8i8op integration — relay board control via TCP/UDP ASCII protocol."""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import ConfigEntry, ConfigEntryState
from homeassistant.const import CONF_HOST, CONF_PORT, Platform
from homeassistant.core import HomeAssistant, ServiceCall, SupportsResponse
from homeassistant.helpers import config_validation as cv, device_registry as dr
from homeassistant.helpers.typing import ConfigType

from homeassistant.helpers.update_coordinator import UpdateFailed

from .const import (
    CONF_CHANNEL_COUNT,
    CONF_PROTOCOL,
    DEFAULT_CHANNEL_COUNT,
    DEFAULT_PORT,
    DEVICE_MODE_LABELS,
    DEVICE_TO_INPUT_MODE,
    DOMAIN,
    INPUT_MODE_AUTO,
    INPUT_MODE_UNLINKED,
    INPUT_MODE_TO_DEVICE,
    MAX_CHANNEL_COUNT,
    INPUT_MODE_TRIGGER,
    LEGACY_CONF_IP,
    LEGACY_CONF_LIGHTS,
    LEGACY_CONF_NAME,
    OPT_INPUT_MODE,
    OPT_WORK_MODE,
    SERVICE_ALL_OFF,
    SERVICE_ALL_ON,
    SERVICE_READ_DEVICE_CONFIG,
    SERVICE_SET_INPUT_MODE,
    SERVICE_SET_WORK_MODE,
)
from .coordinator import HHCCoordinator, HHCATClient, HHCProtocolClient

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [
    Platform.LIGHT,
    Platform.SWITCH,
    Platform.BUTTON,
    Platform.BINARY_SENSOR,
]

# Legacy YAML schema (v2 compatibility)
LEGACY_YAML_SCHEMA = vol.Schema(
    {
        vol.Optional(LEGACY_CONF_IP): cv.string,
        vol.Optional(CONF_HOST): cv.string,
        vol.Optional(CONF_PORT, default=DEFAULT_PORT): cv.port,
        vol.Optional(LEGACY_CONF_NAME): cv.string,
        vol.Optional(LEGACY_CONF_LIGHTS, default=DEFAULT_CHANNEL_COUNT): vol.All(
            int, vol.Range(min=1, max=MAX_CHANNEL_COUNT)
        ),
        vol.Optional(CONF_CHANNEL_COUNT, default=DEFAULT_CHANNEL_COUNT): vol.All(
            int, vol.Range(min=1, max=MAX_CHANNEL_COUNT)
        ),
    }
)

CONFIG_SCHEMA = vol.Schema({DOMAIN: LEGACY_YAML_SCHEMA}, extra=vol.ALLOW_EXTRA)


def _get_coordinators(hass: HomeAssistant, call: ServiceCall) -> list[HHCCoordinator]:
    """Return coordinators for the selected targets.

    If service call has device/entity targets, map them to coordinators.
    Otherwise fall back to all loaded coordinators for backwards compatibility.
    """
    coordinators: list[HHCCoordinator] = []

    # Collect target device IDs from the service call
    target_device_ids: set[str] | None = None
    if call.target:
        target_device_ids = set()
        # device_id targets
        if "device_id" in call.target:
            target_device_ids.update(call.target["device_id"])
        # entity_id targets -> resolve to device IDs
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

        # Filter by target if specified
        if target_device_ids:
            device_reg = dr.async_get(hass)
            device = device_reg.async_get_device(
                identifiers={(DOMAIN, coordinator.device_id)}
            )
            if device is None or device.id not in target_device_ids:
                continue

        coordinators.append(coordinator)

    return coordinators


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up the hhc-n8i8op integration and register services."""
    yaml_config = config.get(DOMAIN)
    if yaml_config is not None:
        await _handle_legacy_yaml(hass, yaml_config)

    # ── AT+INMODE — button→relay coupling mode ──
    hass.services.async_register(
        DOMAIN,
        SERVICE_SET_INPUT_MODE,
        _async_set_input_mode,
        schema=vol.Schema(
            {
                vol.Required("mode"): vol.In(
                    [INPUT_MODE_UNLINKED, INPUT_MODE_TRIGGER, INPUT_MODE_AUTO]
                ),
            }
        ),
        supports_response=SupportsResponse.NONE,
    )

    # ── AT+MODE — network work mode ──
    hass.services.async_register(
        DOMAIN,
        SERVICE_SET_WORK_MODE,
        _async_set_work_mode,
        schema=vol.Schema(
            {
                vol.Required("mode"): vol.All(int, vol.Range(min=0, max=2)),
            }
        ),
        supports_response=SupportsResponse.NONE,
    )

    # ── Discovery SEARCH — read device configuration ──
    hass.services.async_register(
        DOMAIN,
        SERVICE_READ_DEVICE_CONFIG,
        _async_read_device_config,
        schema=vol.Schema({}),
        supports_response=SupportsResponse.ONLY,
    )

    # ── 'allon' / 'alloff' commands ──
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

    return True


async def _handle_legacy_yaml(hass: HomeAssistant, yaml_config: dict[str, Any]) -> None:
    """Auto-import legacy YAML configuration as a ConfigEntry."""
    host = yaml_config.get(CONF_HOST) or yaml_config.get(LEGACY_CONF_IP)
    if not host:
        _LOGGER.warning("No host/ip found in YAML config for %s", DOMAIN)
        return

    port = yaml_config.get(CONF_PORT, DEFAULT_PORT)
    channel_count = yaml_config.get(CONF_CHANNEL_COUNT) or yaml_config.get(
        LEGACY_CONF_LIGHTS, DEFAULT_CHANNEL_COUNT
    )

    for entry in hass.config_entries.async_entries(DOMAIN):
        if entry.data.get(CONF_HOST) == host or entry.unique_id == host:
            _LOGGER.info(
                "ConfigEntry for %s already exists, skipping YAML import", host
            )
            return

    hass.async_create_task(
        hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": "import"},
            data={
                CONF_HOST: host,
                CONF_PORT: port,
                CONF_PROTOCOL: "udp",
                CONF_CHANNEL_COUNT: channel_count,
            },
        )
    )


async def _async_set_input_mode(call: ServiceCall) -> None:
    """Handle set_input_mode service — send AT+INMODE=<n>."""
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
            _LOGGER.info(
                "Input mode set to '%s' (%d) on %s",
                mode_str,
                mode_val,
                coordinator.host,
            )
        else:
            _LOGGER.error("Failed to set input mode on %s", coordinator.host)


async def _async_set_work_mode(call: ServiceCall) -> None:
    """Handle set_work_mode service — send AT+MODE=<n>.

    WARNING: changing this can break the current connection!
    """
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
            _LOGGER.warning(
                "Work mode changed to %d (%s) on %s — connection may break!",
                mode,
                DEVICE_MODE_LABELS.get(mode, "unknown"),
                coordinator.host,
            )
        else:
            _LOGGER.error("Failed to set work mode on %s", coordinator.host)


async def _async_read_device_config(call: ServiceCall) -> dict[str, Any]:
    """Handle read_device_config — discover device and return its configuration."""
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
            if config.mode is not None
            else None,
            "input_mode": f"{config.inmode} ({DEVICE_TO_INPUT_MODE.get(config.inmode, 'unknown')})"
            if config.inmode is not None
            else None,
            "heartbeat": config.heartbeat,
            "mac": config.mac,
            "name": config.name,
        }

        _LOGGER.info("Device config for %s: %s", coordinator.host, result)
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


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up hhc-n8i8op from a config entry."""
    host: str = entry.data[CONF_HOST]
    port: int = entry.data.get(CONF_PORT, DEFAULT_PORT)
    protocol: str = entry.data.get(CONF_PROTOCOL, "tcp")

    client = HHCProtocolClient(host, port, protocol)
    at_client = HHCATClient(host)
    coordinator = HHCCoordinator(hass, entry, client, at_client)

    # Store coordinator BEFORE first refresh so services can safely access it
    entry.runtime_data = coordinator  # type: ignore[assignment]

    try:
        await coordinator.async_config_entry_first_refresh()
    except (TimeoutError, OSError, UpdateFailed) as exc:
        _LOGGER.warning(
            "Initial refresh failed for %s: %s — will retry on next poll cycle",
            host,
            exc,
        )

    # Read actual device state via SEARCH (read-only, no AT pushes)
    # Only update options with REAL values from the device.
    # If SEARCH fails we keep whatever was there before — never invent defaults.
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
        _LOGGER.info(
            "Device %s reports: mode=%s, inmode=%s",
            host,
            config.mode,
            config.inmode,
        )
    except (TimeoutError, OSError) as exc:
        _LOGGER.debug("Could not read device config during setup for %s: %s", host, exc)

    if needs_update:
        hass.config_entries.async_update_entry(entry, options=current_options)

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry and shut down the coordinator."""
    coordinator: HHCCoordinator | None = entry.runtime_data  # type: ignore[assignment]
    if coordinator is not None:
        await coordinator.shutdown()
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)


async def async_remove_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Clean up after entry removal (just logs for now)."""
    _LOGGER.debug("Removed config entry for %s", entry.data.get(CONF_HOST, "unknown"))


async def async_migrate_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Migrate old entry version if needed."""
    _LOGGER.debug("Migrating from version %s", entry.version)
    return True
