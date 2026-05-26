"""Config flow and options flow for hhc-n8i8op integration.

Discovery lifecycle:
  1. DHCP snooper sees MAC OUI 485300* on the network
     → async_step_dhcp: verify with AT+SEARCH, auto-create entry
  2. User clicks "Add Integration"
     → async_step_user: scan subnet, show found devices
     → async_step_confirm: one-click confirm for discovered device
     → async_step_manual: fallback manual IP entry
  3. DHCP sees a configured device with new IP
     → async_step_dhcp updates the entry's host automatically
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import voluptuous as vol

from homeassistant.helpers.service_info.dhcp import DhcpServiceInfo

from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlowWithReload,
)
from homeassistant.const import CONF_HOST, CONF_PORT
from homeassistant.core import callback
from homeassistant.helpers import selector, config_validation as cv

from .const import (
    AT_PORT,
    CHANNEL_TYPE_LIGHT,
    CHANNEL_TYPE_SWITCH,
    CONF_CHANNEL_COUNT,
    CONF_PROTOCOL,
    DEFAULT_CHANNEL_COUNT,
    DEFAULT_POLL_INTERVAL,
    DEFAULT_PORT,
    DEFAULT_PROTOCOL,
    DEVICE_MODE_LABELS,
    DEVICE_TO_INPUT_MODE,
    DOMAIN,
    INPUT_MODE_TRIGGER,
    INPUT_MODE_UNLINKED,
    INPUT_MODE_TO_DEVICE,
    MODE_UNCHANGED,
    MAX_CHANNEL_COUNT,
    MIN_POLL_INTERVAL,
    MAX_POLL_INTERVAL,
    OPT_CHANNEL_TYPES,
    OPT_DEVICE_NAME,
    OPT_INPUT_MODE,
    OPT_POLL_INTERVAL,
    OPT_WORK_MODE,
)
from .coordinator import HHCCoordinator, HHCATClient

_LOGGER = logging.getLogger(__name__)

_PREFIX_CHANNEL_TYPE = f"{OPT_CHANNEL_TYPES}_"

# Step identifiers
CONF_SELECTED_DEVICE = "selected_device"

# Scan timeout for the "add integration" subnet scan
_SCAN_TIMEOUT: float = 4.0


class HHCConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle initial setup of a new hhc-n8i8op device.

    Three entry points:
      - DHCP discovery (automatic)
      - User-initiated scan (Add Integration button)
      - Manual entry (fallback)
    """

    VERSION = 1

    def __init__(self) -> None:
        """Initialize the config flow."""
        self._discovered_devices: dict[str, dict[str, Any]] = {}
        self._dhcp_info: DhcpServiceInfo | None = None
        self._selected_device: dict[str, Any] | None = None

    # ── DHCP Discovery ────────────────────────────────────────────────────

    async def async_step_dhcp(
        self, discovery_info: DhcpServiceInfo
    ) -> ConfigFlowResult:
        """Handle DHCP discovery — HA saw an HHC MAC on the network.

        Two scenarios:
          A) New device → verify with SEARCH, create config entry
          B) Existing device changed IP → update host in existing entry
        """
        ip = discovery_info.ip
        mac = discovery_info.macaddress

        _LOGGER.info("DHCP discovery triggered: IP=%s MAC=%s", ip, mac)

        await self.async_set_unique_id(mac)

        # If already configured — update IP if it changed, then abort.
        # We must update data BEFORE reload so the coordinator reconnects
        # to the correct address.
        for entry in self._async_current_entries():
            if entry.unique_id == mac:
                current_host = entry.data.get(CONF_HOST)
                if current_host != ip:
                    _LOGGER.info(
                        "DHCP: device %s changed IP %s → %s, updating entry",
                        mac, current_host, ip,
                    )
                    new_data = dict(entry.data)
                    new_data[CONF_HOST] = ip
                    self.hass.config_entries.async_update_entry(entry, data=new_data)
                    # Schedule reload so the coordinator reconnects to new IP
                    self.hass.async_create_task(
                        self.hass.config_entries.async_reload(entry.entry_id)
                    )
                else:
                    _LOGGER.debug("DHCP: device %s at same IP %s, ignoring", mac, ip)
                self.async_abort(reason="already_configured")
                # async_abort raises, but type checker doesn't know that
                return self.async_abort(reason="already_configured")  # pragma: no cover

        # New device — verify with targeted AT+SEARCH broadcast
        _LOGGER.info("DHCP: new device %s at %s, verifying with AT+SEARCH...", mac, ip)
        cfg = None
        try:
            cfg = await HHCATClient.discover(ip, timeout=10.0)
        except Exception as exc:
            _LOGGER.warning("DHCP: SEARCH failed for %s: %s", ip, exc)

        if cfg is not None and cfg.ip == ip:
            dev_name = cfg.name or ""
            title = f"{dev_name} ({ip})" if dev_name else f"hhc n8i8op ({ip})"
            protocol = "udp" if cfg.mode == 2 else "tcp"
            _LOGGER.info(
                "DHCP: confirmed device %s (name=%s mode=%s proto=%s), creating entry",
                mac, dev_name, cfg.mode, protocol,
            )
            return self.async_create_entry(
                title=title,
                data={
                    CONF_HOST: ip,
                    CONF_PORT: cfg.local_port or DEFAULT_PORT,
                    CONF_PROTOCOL: protocol,
                    CONF_CHANNEL_COUNT: DEFAULT_CHANNEL_COUNT,
                },
                options={
                    OPT_POLL_INTERVAL: DEFAULT_POLL_INTERVAL,
                    OPT_CHANNEL_TYPES: {},
                    OPT_DEVICE_NAME: dev_name,
                    OPT_INPUT_MODE: DEVICE_TO_INPUT_MODE.get(
                        cfg.inmode, INPUT_MODE_TRIGGER
                    )
                    if cfg.inmode is not None
                    else INPUT_MODE_TRIGGER,
                    OPT_WORK_MODE: str(cfg.mode) if cfg.mode is not None else "0",
                },
            )

        # SEARCH didn't confirm — let user set up manually with this IP pre-filled
        _LOGGER.warning(
            "DHCP: SEARCH could not confirm device at %s, falling back to manual setup",
            ip,
        )
        self._dhcp_info = discovery_info
        return await self.async_step_manual()

    # ── User-initiated setup ──────────────────────────────────────────────

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """User clicked 'Add Integration' — scan network, show found devices.

        Scans all local /24 subnets using AT+SEARCH broadcasts.
        If devices found → shows pick list + manual option.
        If nothing found → falls straight to manual entry.
        """
        if user_input is not None and CONF_SELECTED_DEVICE in user_input:
            selected_ip = user_input[CONF_SELECTED_DEVICE]
            device_info = self._discovered_devices.get(selected_ip)
            if device_info is not None:
                # Store selection for confirmation step
                self._selected_device = device_info
                _LOGGER.info("User selected device at %s", selected_ip)
                return await self.async_step_confirm()
            # "manual" or invalid → go to manual entry
            _LOGGER.info("User chose manual entry")
            return await self.async_step_manual()

        # Run subnet scan to find all HHC devices
        _LOGGER.info("Starting network scan (AT+SEARCH broadcast on port %d)", AT_PORT)
        discovered = await self._scan_network()

        if not discovered:
            # No devices found → skip straight to manual
            _LOGGER.info("Network scan found no devices, showing manual entry form")
            return await self.async_step_manual()

        self._discovered_devices = discovered

        # Build dropdown: each found device + manual option
        device_options: list[selector.SelectOptionDict] = []
        for ip_addr, info in sorted(discovered.items()):
            label = f"{info.get('_devname', 'hhc n8i8op')} ({ip_addr})"
            device_options.append({"value": ip_addr, "label": label})
        device_options.append({"value": "manual", "label": "Enter manually..."})

        schema = vol.Schema(
            {
                vol.Required(CONF_SELECTED_DEVICE): selector.SelectSelector(
                    selector.SelectSelectorConfig(
                        options=device_options,
                        mode=selector.SelectSelectorMode.DROPDOWN,
                    )
                ),
            }
        )

        return self.async_show_form(
            step_id="user",
            data_schema=schema,
        )

    async def async_step_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Confirm adding a discovered device — one click."""
        info = self._selected_device

        # Safety: if no device was selected (e.g. direct URL access), go back
        if info is None:
            return await self.async_step_user()

        if user_input is not None:
            mac = info.get("_mac") or info[CONF_HOST]
            await self.async_set_unique_id(mac)
            self._abort_if_unique_id_configured()

            dev_name = info.get("_devname", "")
            ip_addr = info[CONF_HOST]
            title = f"{dev_name} ({ip_addr})" if dev_name else f"hhc n8i8op ({ip_addr})"
            _LOGGER.info(
                "Creating entry for %s: name=%s mac=%s proto=%s port=%d",
                ip_addr, dev_name, mac, info[CONF_PROTOCOL], info[CONF_PORT],
            )
            return self.async_create_entry(
                title=title,
                data={
                    CONF_HOST: ip_addr,
                    CONF_PORT: info[CONF_PORT],
                    CONF_PROTOCOL: info[CONF_PROTOCOL],
                    CONF_CHANNEL_COUNT: info[CONF_CHANNEL_COUNT],
                },
                options={
                    OPT_POLL_INTERVAL: DEFAULT_POLL_INTERVAL,
                    OPT_CHANNEL_TYPES: {},
                    OPT_DEVICE_NAME: dev_name,
                    OPT_INPUT_MODE: DEVICE_TO_INPUT_MODE.get(
                        info.get("_inmode", 1), INPUT_MODE_TRIGGER
                    ),
                    OPT_WORK_MODE: str(info.get("_mode", 0)),
                },
            )

        # Show confirmation form (just a Submit button)
        ip_addr = info[CONF_HOST] if info else "?"
        dev_name = info.get("_devname", "") if info else ""

        return self.async_show_form(
            step_id="confirm",
            description_placeholders={
                "device": f"{dev_name} ({ip_addr})" if dev_name else ip_addr,
            },
        )

    async def async_step_manual(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Manual entry — user enters IP and optional port.

        Auto-detects TCP vs UDP. Port defaults to 5000 but user can override.
        """
        errors: dict[str, str] = {}

        if user_input is not None:
            host: str = user_input[CONF_HOST]
            port: int = user_input.get(CONF_PORT, DEFAULT_PORT)

            # Auto-detect protocol via probe (TCP + UDP in parallel)
            protocol: str | None = None
            try:
                protocol = await HHCATClient.probe(host, port=port, timeout=5.0)
            except Exception as exc:
                _LOGGER.debug("Probe failed for %s:%d: %s", host, port, exc)

            if protocol is None:
                errors["base"] = "cannot_connect"
            else:
                _LOGGER.info("Manual setup: probe detected %s:%d → %s", host, port, protocol)

                unique_id = (
                    self._dhcp_info.macaddress
                    if self._dhcp_info is not None
                    else host
                )
                await self.async_set_unique_id(unique_id)
                self._abort_if_unique_id_configured()

                return self.async_create_entry(
                    title=f"hhc n8i8op ({host})",
                    data={
                        CONF_HOST: host,
                        CONF_PORT: port,
                        CONF_PROTOCOL: protocol,
                        CONF_CHANNEL_COUNT: DEFAULT_CHANNEL_COUNT,
                    },
                    options={
                        OPT_POLL_INTERVAL: DEFAULT_POLL_INTERVAL,
                        OPT_CHANNEL_TYPES: {},
                    },
                )

        default_host = self._dhcp_info.ip if self._dhcp_info is not None else ""

        schema = vol.Schema({
            vol.Required(CONF_HOST, default=default_host): str,
            vol.Optional(CONF_PORT, default=DEFAULT_PORT): cv.positive_int,
        })

        return self.async_show_form(step_id="manual", data_schema=schema, errors=errors)

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> HHCOptionsFlow:
        """Return the options flow handler."""
        return HHCOptionsFlow()

    async def async_step_import(self, import_data: dict[str, Any]) -> ConfigFlowResult:
        """Handle import from legacy YAML configuration (v2 compatibility)."""
        host: str = import_data[CONF_HOST]
        port: int = import_data.get(CONF_PORT, DEFAULT_PORT)
        protocol: str = import_data.get(CONF_PROTOCOL, "udp")
        channel_count: int = import_data.get(CONF_CHANNEL_COUNT, DEFAULT_CHANNEL_COUNT)

        await self.async_set_unique_id(host)
        self._abort_if_unique_id_configured()

        _LOGGER.info(
            "Importing YAML config for %s:%d (%s, %d channels)",
            host,
            port,
            protocol,
            channel_count,
        )

        return self.async_create_entry(
            title=f"hhc n8i8op ({host})",
            data={
                CONF_HOST: host,
                CONF_PORT: port,
                CONF_PROTOCOL: protocol,
                CONF_CHANNEL_COUNT: channel_count,
            },
            options={
                OPT_POLL_INTERVAL: DEFAULT_POLL_INTERVAL,
                OPT_CHANNEL_TYPES: {},
            },
        )

    # ── Internal helpers ───────────────────────────────────────────────────

    async def _scan_network(self) -> dict[str, dict[str, Any]]:
        """Scan all local subnets for HHC devices.

        Sends AT+SEARCH broadcast on all interfaces and collects responses.
        Returns {ip: device_info_dict}.

        IMPORTANT: does NOT mutate self.unique_id — that must only be set
        once the user actually picks a device (in async_step_confirm).
        Already-configured devices are filtered out by checking existing
        config entries' unique_ids against discovered MACs/IPs.
        """
        results: dict[str, dict[str, Any]] = {}

        try:
            devices = await HHCATClient.scan_subnet(timeout=_SCAN_TIMEOUT)
        except Exception as exc:
            _LOGGER.warning("Subnet scan failed: %s", exc)
            return results

        # Build set of already-configured unique IDs to filter out
        configured_uids: set[str] = {
            entry.unique_id
            for entry in self.hass.config_entries.async_entries(DOMAIN)
            if entry.unique_id is not None
        }
        _LOGGER.debug(
            "Already configured unique IDs: %s", configured_uids or "(none)",
        )

        for ip_addr, cfg in devices:
            uid = cfg.mac or ip_addr
            if uid in configured_uids:
                _LOGGER.debug("Skipping already configured device %s (%s)", ip_addr, uid)
                continue

            protocol = "udp" if cfg.mode == 2 else "tcp"
            results[ip_addr] = {
                CONF_HOST: ip_addr,
                CONF_PORT: cfg.local_port or DEFAULT_PORT,
                CONF_PROTOCOL: protocol,
                CONF_CHANNEL_COUNT: DEFAULT_CHANNEL_COUNT,
                "_devname": cfg.name or "",
                "_mac": cfg.mac or "",
                "_inmode": cfg.inmode,
                "_mode": cfg.mode,
            }

        _LOGGER.info(
            "Network scan found %d device(s), %d new unconfigured",
            len(devices), len(results),
        )
        return results


class HHCOptionsFlow(OptionsFlowWithReload):
    """Handle options changes — auto-reload on save.

    IMPORTANT: Before showing the form, we READ current values from the
    physical device via SEARCH. This ensures the user always sees the
    ACTUAL device state — not stale HA options.

    If the device couldn't be queried (SEARCH timeout), dropdown defaults
    to saved options but includes a "(no change)" sentinel so the user
    isn't forced to pick a value that may be wrong.
    """

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Main options step."""
        if user_input is not None:
            channel_types = _extract_prefixed(user_input, _PREFIX_CHANNEL_TYPE)

            cleaned = {
                k: v
                for k, v in user_input.items()
                if not k.startswith(_PREFIX_CHANNEL_TYPE) and k != OPT_DEVICE_NAME
            }
            cleaned[OPT_CHANNEL_TYPES] = channel_types

            new_name: str = user_input.get(OPT_DEVICE_NAME, "")
            cleaned[OPT_DEVICE_NAME] = new_name

            old_name: str = self.config_entry.options.get(OPT_DEVICE_NAME, "")
            if new_name != old_name and new_name:
                success = await self._apply_device_name(new_name)
                if success:
                    host = self.config_entry.data.get(CONF_HOST, "")
                    new_title = (
                        f"{new_name} ({host})" if new_name else f"hhc n8i8op ({host})"
                    )
                    self.hass.config_entries.async_update_entry(
                        self.config_entry, title=new_title
                    )

            # ── Input mode ──────────────────────────────────────────────
            # We ALWAYS send the selected mode to the device on Save,
            # UNLESS the user explicitly picked "don't change".
            # This fixes the case where saved options diverge from the
            # real device state (e.g. device is in "Unlinked" but HA shows
            # "Trigger") — user sees Trigger pre-selected, clicks Save,
            # and the command actually gets sent.
            new_mode = user_input.get(OPT_INPUT_MODE, MODE_UNCHANGED)
            if new_mode == MODE_UNCHANGED:
                # User chose "don't change" — keep existing option value
                final_mode = self.config_entry.options.get(
                    OPT_INPUT_MODE, INPUT_MODE_TRIGGER
                )
            else:
                # User picked a concrete mode — push it to device regardless
                # of what the old saved option was. Even if they picked the
                # same label that was already showing, the real device might
                # be in a different state, so we always send.
                success = await self._apply_input_mode(new_mode)
                final_mode = (
                    new_mode
                    if success
                    else (
                        self.config_entry.options.get(
                            OPT_INPUT_MODE, INPUT_MODE_TRIGGER
                        )
                    )
                )
            cleaned[OPT_INPUT_MODE] = final_mode

            # ── Work mode — same pattern ────────────────────────────────
            new_work = user_input.get(OPT_WORK_MODE, MODE_UNCHANGED)
            if new_work == MODE_UNCHANGED:
                final_work = self.config_entry.options.get(OPT_WORK_MODE, "0")
            else:
                success = await self._apply_work_mode(int(new_work))
                final_work = (
                    new_work
                    if success
                    else (self.config_entry.options.get(OPT_WORK_MODE, "0"))
                )
            cleaned[OPT_WORK_MODE] = final_work

            return self.async_create_entry(data=cleaned)

        # Read actual device config first, then fall back to stored options.
        coordinator: HHCCoordinator | None = getattr(
            self.config_entry, "runtime_data", None
        )
        device_config = None
        if coordinator is not None:
            try:
                device_config = await coordinator.read_device_config()
                _LOGGER.info(
                    "Options flow: read device config — inmode=%s, mode=%s, name=%s",
                    device_config.inmode,
                    device_config.mode,
                    device_config.name,
                )
            except Exception:
                _LOGGER.warning("Could not read device config for options form: %s", exc)

        # Determine input mode default + options list.
        #
        # Key UX rule: if we successfully queried the device, dropdown shows
        # the REAL device value pre-selected. The user can then pick any mode
        # and it will be pushed on Save — even if they "re-select" the same
        # value that's already showing (because saved option may differ).
        #
        # If we COULDN'T query the device, we add a "_unchanged" sentinel so
        # the user can explicitly say "skip this, don't send anything".
        if device_config is not None and device_config.inmode is not None:
            real_mode = DEVICE_TO_INPUT_MODE.get(device_config.inmode)
            if real_mode is not None:
                current_mode = real_mode
                mode_options = [INPUT_MODE_UNLINKED, INPUT_MODE_TRIGGER]
            else:
                # Unknown inmode value from device — show stored with sentinel
                current_mode = self.config_entry.options.get(
                    OPT_INPUT_MODE, MODE_UNCHANGED
                )
                mode_options = [MODE_UNCHANGED, INPUT_MODE_UNLINKED, INPUT_MODE_TRIGGER]
        else:
            # Device unreachable — show stored value but let user opt out
            current_mode = self.config_entry.options.get(OPT_INPUT_MODE, MODE_UNCHANGED)
            mode_options = [MODE_UNCHANGED, INPUT_MODE_UNLINKED, INPUT_MODE_TRIGGER]

        # Same pattern for work mode
        if device_config is not None and device_config.mode is not None:
            current_work = str(device_config.mode)
            work_options = [str(k) for k in sorted(DEVICE_MODE_LABELS)]
        else:
            current_work = self.config_entry.options.get(OPT_WORK_MODE, MODE_UNCHANGED)
            work_options = [
                MODE_UNCHANGED,
                *[str(k) for k in sorted(DEVICE_MODE_LABELS)],
            ]

        current_name: str = self.config_entry.options.get(OPT_DEVICE_NAME, "")
        if device_config is not None and device_config.name:
            current_name = device_config.name

        current_poll: float = self.config_entry.options.get(
            OPT_POLL_INTERVAL, DEFAULT_POLL_INTERVAL
        )

        channel_count: int = self.config_entry.data.get(
            CONF_CHANNEL_COUNT, DEFAULT_CHANNEL_COUNT
        )
        current_types: dict[str, str] = self.config_entry.options.get(
            OPT_CHANNEL_TYPES, {}
        )

        schema_dict: dict[vol.Marker, Any] = {
            vol.Optional(OPT_DEVICE_NAME, default=current_name): str,
            vol.Optional(
                OPT_POLL_INTERVAL, default=current_poll
            ): selector.NumberSelector(
                selector.NumberSelectorConfig(
                    mode=selector.NumberSelectorMode.SLIDER,
                    min=MIN_POLL_INTERVAL,
                    max=MAX_POLL_INTERVAL,
                    step=0.1,
                    unit_of_measurement="sec",
                )
            ),
            vol.Optional(OPT_INPUT_MODE, default=current_mode): selector.SelectSelector(
                selector.SelectSelectorConfig(
                    options=mode_options,
                    translation_key="input_mode",
                    mode=selector.SelectSelectorMode.DROPDOWN,
                )
            ),
            vol.Optional(OPT_WORK_MODE, default=current_work): selector.SelectSelector(
                selector.SelectSelectorConfig(
                    options=work_options,
                    translation_key="work_mode",
                    mode=selector.SelectSelectorMode.DROPDOWN,
                )
            ),
        }

        for ch in range(channel_count):
            ct_key = f"{_PREFIX_CHANNEL_TYPE}{ch}"
            ct_default = current_types.get(str(ch), CHANNEL_TYPE_SWITCH)
            schema_dict[vol.Optional(ct_key, default=ct_default)] = (
                selector.SelectSelector(
                    selector.SelectSelectorConfig(
                        options=[CHANNEL_TYPE_SWITCH, CHANNEL_TYPE_LIGHT],
                        translation_key="channel_type",
                        mode=selector.SelectSelectorMode.DROPDOWN,
                    )
                )
            )

        return self.async_show_form(step_id="init", data_schema=vol.Schema(schema_dict))

    async def _apply_device_name(self, name: str) -> bool:
        """Push device name to the physical device."""
        coordinator: HHCCoordinator | None = getattr(
            self.config_entry, "runtime_data", None
        )
        if coordinator is None:
            _LOGGER.warning("Cannot apply device name — coordinator not available")
            return False

        success = await coordinator.at_client.set_device_name(name)
        if success:
            _LOGGER.info("Applied device name '%s' to %s", name, coordinator.host)
        else:
            _LOGGER.warning(
                "Failed to apply device name '%s' to %s", name, coordinator.host
            )

        return success

    async def _apply_input_mode(self, mode: str) -> bool:
        """Push input mode setting to the physical device."""
        coordinator: HHCCoordinator | None = getattr(
            self.config_entry, "runtime_data", None
        )
        if coordinator is None:
            _LOGGER.warning("Cannot apply input mode — coordinator not available")
            return False

        mode_val = INPUT_MODE_TO_DEVICE.get(mode, 1)
        success = await coordinator.transition_mode(
            lambda mv=mode_val: coordinator.at_client.set_input_mode(mv),
        )

        if success:
            _LOGGER.info(
                "Applied input mode '%s' (%d) to device %s",
                mode,
                mode_val,
                coordinator.host,
            )
        else:
            _LOGGER.warning(
                "Failed to apply input mode '%s' to device %s",
                mode,
                coordinator.host,
            )

        return success

    async def _apply_work_mode(self, mode: int) -> bool:
        """Push work mode setting to the physical device."""
        coordinator: HHCCoordinator | None = getattr(
            self.config_entry, "runtime_data", None
        )
        if coordinator is None:
            _LOGGER.warning("Cannot apply work mode — coordinator not available")
            return False

        success = await coordinator.transition_mode(
            lambda m=mode: coordinator.at_client.set_work_mode(m),
        )

        if success:
            _LOGGER.info(
                "Applied work mode %d (%s) to device %s",
                mode,
                DEVICE_MODE_LABELS.get(mode, "unknown"),
                coordinator.host,
            )
        else:
            _LOGGER.warning(
                "Failed to apply work mode %d to device %s",
                mode,
                coordinator.host,
            )

        return success


def _extract_prefixed(user_input: dict[str, Any], prefix: str) -> dict[str, str]:
    """Convert flat 'prefix_N' keys back to {str(index): value} dict."""
    result: dict[str, str] = {}
    for key, value in user_input.items():
        if key.startswith(prefix):
            index_str = key[len(prefix) :]
            result[index_str] = str(value)
    return result
