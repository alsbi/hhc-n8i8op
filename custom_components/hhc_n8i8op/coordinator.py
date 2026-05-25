"""hhc-n8i8op DataUpdateCoordinator for Home Assistant."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import (
    DataUpdateCoordinator,
    UpdateFailed,
)

from .const import (
    CHANNEL_TYPE_LIGHT,
    CONF_CHANNEL_COUNT,
    DEFAULT_CHANNEL_COUNT,
    DEFAULT_POLL_INTERVAL,
    DOMAIN,
    EVENT_INPUT_CHANGED,
    GLOBAL_INPUT_ALL_OFF,
    GLOBAL_INPUT_ALL_ON,
    INPUT_MODE_TO_DEVICE,
    INPUT_MODE_TRIGGER,
    OPT_CHANNEL_TYPES,
    OPT_DEVICE_NAME,
    OPT_INPUT_MODE,
    OPT_POLL_INTERVAL,
)
from .hhc_protocol import (
    HHCClient as HHCATClient,
    HHCDeviceConfig,
    HHCRelayClient as HHCProtocolClient,
)

_LOGGER = logging.getLogger(__name__)


# ── HA-specific data structures ───────────────────────────────────────────────


@dataclass
class HHCDeviceState:
    """Current state of outputs and inputs."""

    outputs: list[bool] = field(default_factory=list)
    inputs: list[bool] = field(default_factory=list)
    global_on: bool = False
    global_off: bool = False


# ── Coordinator ──────────────────────────────────────────────────────────────


class HHCCoordinator(DataUpdateCoordinator[HHCDeviceState]):
    """Coordinator for hhc-n8i8op — polls outputs and inputs every cycle.

    IMPORTANT: Commands go through a single asyncio.Lock per client.
    We must poll sequentially, NOT via asyncio.gather, otherwise the
    second command blocks waiting for the lock until the first completes
    anyway — and with TCP it can even cause issues with interleaved reads.
    """

    config_entry: ConfigEntry  # type: ignore[assignment]

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        client: HHCProtocolClient,
        at_client: HHCATClient | None = None,
    ) -> None:
        self.client = client
        self.at_client = at_client or HHCATClient(client.host)
        self._prev_inputs: list[bool] | None = None
        self._transitioning: bool = False  # True while device reboots after mode change
        self._transition_task: asyncio.Task | None = None  # background resume task
        poll_interval = entry.options.get(OPT_POLL_INTERVAL, DEFAULT_POLL_INTERVAL)
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN} {client.host}",
            config_entry=entry,
            update_interval=timedelta(seconds=poll_interval),
            always_update=False,
        )

    @property
    def host(self) -> str:
        return self.client.host

    @property
    def device_id(self) -> str:
        """Unique identifier for Device Registry grouping."""
        return self.client.host

    @property
    def device_name(self) -> str:
        stored = self.config_entry.options.get(OPT_DEVICE_NAME, "")
        if stored:
            return f"{stored} ({self.client.host})"
        return f"hhc n8i8op ({self.client.host})"

    @property
    def channel_count(self) -> int:
        return self.config_entry.data.get(CONF_CHANNEL_COUNT, DEFAULT_CHANNEL_COUNT)

    def is_channel_light(self, channel: int) -> bool:
        """Check if a channel should be exposed as light instead of switch."""
        types: dict[str, str] = self.config_entry.options.get(OPT_CHANNEL_TYPES, {})
        return types.get(str(channel), "switch") == CHANNEL_TYPE_LIGHT

    def get_input_mode(self) -> str:
        """Return current input mode setting ('ordinary', 'trigger', 'auto')."""
        return self.config_entry.options.get(OPT_INPUT_MODE, INPUT_MODE_TRIGGER)

    async def read_device_config(self) -> HHCDeviceConfig:
        """Read current device configuration via SEARCH discovery.

        Returns cached config if SEARCH times out. Never returns
        an empty/default config that would be dangerous to write back.
        """
        config = await self.at_client.read_config()
        if config is not None:
            return config
        # Return cached config from previous successful SEARCH
        if self.at_client._cached_config is not None:
            _LOGGER.warning("Using cached device config for %s", self.host)
            return self.at_client._cached_config
        # No config at all — return empty as informational only (NOT for writing!)
        _LOGGER.warning("No device config available for %s", self.host)
        return HHCDeviceConfig()

    async def apply_input_mode_to_device(self) -> bool:
        """Push current HA input_mode option to the physical device."""
        mode_str = self.get_input_mode()
        mode_val = INPUT_MODE_TO_DEVICE.get(mode_str, 1)
        return await self.at_client.set_input_mode(mode_val)

    async def transition_mode(
        self,
        apply_fn: Callable[[], Awaitable[bool]],
        *,
        wait_seconds: float = 5.0,
    ) -> bool:
        """Apply a mode change and guard commands while device reboots.

        Sets ``_transitioning = True`` so that all relay commands are
        silently ignored until the device is expected to come back online.
        After *wait_seconds* the flag is cleared and a fresh poll runs.
        """
        if self._transitioning:
            _LOGGER.warning(
                "Already transitioning — ignoring duplicate mode change request"
            )
            return False

        success = await apply_fn()
        if not success:
            return False

        # Device reboots after AT+SAVE=1 (~3-5 sec)
        self._transitioning = True
        _LOGGER.info(
            "Mode change applied — device rebooting, commands paused for %.1fs",
            wait_seconds,
        )

        async def _resume() -> None:
            await asyncio.sleep(wait_seconds)
            self._transitioning = False
            _LOGGER.info("Device should be back online — resuming commands")
            await self.async_request_refresh()

        self._transition_task = self.hass.async_create_background_task(
            _resume(), name="hhc_transition_resume"
        )
        return True

    async def shutdown(self) -> None:
        """Cancel background tasks, stop refresh, close connections."""
        if self._transition_task and not self._transition_task.done():
            self._transition_task.cancel()
            try:
                await self._transition_task
            except asyncio.CancelledError:
                pass
        # Close persistent TCP
        await self.client.shutdown()

    async def _async_update_data(self) -> HHCDeviceState:
        """Fetch outputs and (when needed) inputs from the device.

        In **trigger** mode the physical buttons are hard-wired to their
        matching relays — querying ``input`` is redundant because every
        button press already toggled the relay and will be reflected in
        the ``read`` response.  Skipping ``input`` halves the background
        traffic in this common case.

        In **unlinked** mode buttons are decoupled so we MUST poll
        ``input`` to detect physical presses.
        """
        # --- Skip polling while device is rebooting after mode change ---
        if self._transitioning:
            _LOGGER.debug("Skipping poll — device rebooting after mode change")
            if self.data:
                return self.data
            return HHCDeviceState(
                outputs=[], inputs=[], global_on=False, global_off=False
            )

        # --- Fetch outputs (always needed) ---
        try:
            raw_outputs = await self.client.send_command("read")
            outputs = HHCProtocolClient.parse_relay_response(
                raw_outputs, self.channel_count
            )
        except (TimeoutError, OSError, UnicodeDecodeError) as exc:
            raise UpdateFailed(f"Failed to read relays: {exc}") from exc

        # --- Fetch inputs only when they carry independent information ---
        inputs: list[bool] = []
        global_on = self.data.global_on if self.data else False
        global_off = self.data.global_off if self.data else False

        need_inputs = self.get_input_mode() != INPUT_MODE_TRIGGER

        if need_inputs:
            try:
                raw_inputs = await self.client.send_command("input")
                all_bits = HHCProtocolClient.parse_full_input_response(raw_inputs)
                for ch in range(self.channel_count):
                    inputs.append(all_bits[ch] if ch < len(all_bits) else False)
                global_on_idx = self.channel_count + GLOBAL_INPUT_ALL_ON
                global_off_idx = self.channel_count + GLOBAL_INPUT_ALL_OFF
                global_on = (
                    all_bits[global_on_idx] if global_on_idx < len(all_bits) else False
                )
                global_off = (
                    all_bits[global_off_idx]
                    if global_off_idx < len(all_bits)
                    else False
                )
            except (TimeoutError, OSError, UnicodeDecodeError) as exc:
                _LOGGER.warning("Failed to read inputs: %s", exc)
                inputs = (
                    list(self._prev_inputs) if self._prev_inputs is not None else []
                )
        else:
            # Trigger mode: inputs mirror outputs — derive from relay state
            inputs = (
                list(outputs[: self.channel_count])
                if len(outputs) >= self.channel_count
                else [False] * self.channel_count
            )
            # Still carry over previous global input states until next full poll
            if self.data and self.data.inputs:
                _LOGGER.debug("Trigger mode — skipping input poll for %s", self.host)

        self._fire_input_events(inputs)
        self._prev_inputs = list(inputs)

        return HHCDeviceState(
            outputs=outputs, inputs=inputs, global_on=global_on, global_off=global_off
        )

    def _fire_input_events(self, current_inputs: list[bool]) -> None:
        """Fire EVENT_INPUT_CHANGED for each input that changed state."""
        if self._prev_inputs is None:
            return

        for i, current_val in enumerate(current_inputs):
            if i >= len(self._prev_inputs):
                continue
            if self._prev_inputs[i] != current_val:
                self.hass.bus.async_fire(
                    EVENT_INPUT_CHANGED,
                    {
                        "device_id": self.device_id,
                        "input": i + 1,
                        "state": current_val,
                        "mode": self.get_input_mode(),
                    },
                )

    async def set_output(self, channel: int, state: bool) -> None:
        """Turn a relay on or off — update state from device response.

        The board replies to on/off commands with the full relay state
        string (e.g. ``relay01000000``), so we parse that directly and
        skip any extra ``read`` + ``input`` round-trips. If the response
        doesn't contain relay data we fall back to optimistic update.
        """
        if self._transitioning:
            _LOGGER.warning(
                "Ignoring relay command — device is rebooting after mode change"
            )
            return
        cmd = f"on{channel + 1}" if state else f"off{channel + 1}"
        raw = await self.client.send_command(cmd)
        self._update_from_relay_response(
            raw, fallback_channel=channel, fallback_state=state
        )

    async def set_all_on(self) -> None:
        """Turn ALL relays on at once."""
        if self._transitioning:
            _LOGGER.warning(
                "Ignoring all_on command — device is rebooting after mode change"
            )
            return
        raw = await self.client.send_command("allon")
        self._update_from_relay_response(raw, fallback_state=True)

    async def set_all_off(self) -> None:
        """Turn ALL relays off at once."""
        if self._transitioning:
            _LOGGER.warning(
                "Ignoring all_off command — device is rebooting after mode change"
            )
            return
        raw = await self.client.send_command("alloff")
        self._update_from_relay_response(raw, fallback_state=False)

    # ── State update helpers ──

    def _update_from_relay_response(
        self,
        raw: str,
        *,
        fallback_channel: int | None = None,
        fallback_state: bool | None = None,
    ) -> None:
        """Parse relay state from command response and push to HA.

        The N8I8OP returns ``relay01000000`` as response to on/off/allon/alloff
        commands. When available, this gives us the REAL state of all outputs
        without needing a separate ``read`` poll.

        Falls back to optimistic single-channel update if the response isn't
        a relay state string (some firmware versions echo just the command).
        """
        if self.data is None:
            return

        try:
            outputs = HHCProtocolClient.parse_relay_response(raw, self.channel_count)
        except (ValueError, TypeError):
            # Response wasn't "relayXXXXXXXX" — optimise just the affected channel
            if fallback_channel is not None and fallback_state is not None:
                self._apply_optimistic_update(fallback_channel, fallback_state)
            elif fallback_state is not None:
                self._apply_optimistic_update_all(fallback_state)
            return

        updated = HHCDeviceState(
            outputs=outputs,
            inputs=list(self.data.inputs) if self.data.inputs else [],
            global_on=self.data.global_on,
            global_off=self.data.global_off,
        )
        self.async_set_updated_data(updated)

    def _apply_optimistic_update(self, channel: int, state: bool) -> None:
        """Optimistic single-channel update when device response can't be parsed."""
        if len(self.data.outputs) > channel and self.data.outputs[channel] == state:
            return  # already matches
        updated = HHCDeviceState(
            outputs=list(self.data.outputs),
            inputs=list(self.data.inputs) if self.data.inputs else [],
            global_on=self.data.global_on,
            global_off=self.data.global_off,
        )
        updated.outputs[channel] = state
        self.async_set_updated_data(updated)

    def _apply_optimistic_update_all(self, state: bool) -> None:
        """Optimistic all-channels update when device response can't be parsed."""
        updated = HHCDeviceState(
            outputs=[state] * max(len(self.data.outputs), self.channel_count),
            inputs=list(self.data.inputs) if self.data.inputs else [],
            global_on=self.data.global_on,
            global_off=self.data.global_off,
        )
        self.async_set_updated_data(updated)
