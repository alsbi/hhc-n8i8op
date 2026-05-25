"""Base entity classes for hhc-n8i8op integration."""

from __future__ import annotations

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import HHCCoordinator


class HHCEntity(CoordinatorEntity[HHCCoordinator]):
    """Base output (relay) entity.

    Groups all entities into a single device in Device Registry.
    Provides shared logic for available, is_on, async_turn_on/off
    used by both SwitchEntity and LightEntity subclasses.

    Each output channel knows its linked input via extra_state_attributes.
    """

    _attr_has_entity_name = True

    def __init__(self, coordinator: HHCCoordinator, channel: int) -> None:
        super().__init__(coordinator)
        self._channel = channel
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, coordinator.device_id)},
            name=coordinator.device_name,
            manufacturer="HHC",
            model="N8I8OP",
            configuration_url=f"http://{coordinator.host}",
        )

    @property
    def available(self) -> bool:
        """Return True if coordinator has data for this channel."""
        return (
            self.coordinator.last_update_success
            and self.coordinator.data is not None
            and len(self.coordinator.data.outputs) > self._channel
        )

    @property
    def relay_is_on(self) -> bool | None:
        """Return true if the relay channel is on."""
        if (
            self.coordinator.data is None
            or len(self.coordinator.data.outputs) <= self._channel
        ):
            return None
        return self.coordinator.data.outputs[self._channel]

    @property
    def extra_state_attributes(self) -> dict[str, str]:
        """Return input mode attribute."""
        return {
            "input_mode": self.coordinator.get_input_mode(),
        }

    async def async_turn_relay_on(self) -> None:
        """Turn the relay channel on."""
        await self.coordinator.set_output(self._channel, True)

    async def async_turn_relay_off(self) -> None:
        """Turn the relay channel off."""
        await self.coordinator.set_output(self._channel, False)


class HHCInputEntity(CoordinatorEntity[HHCCoordinator]):
    """Base input entity for physical input binary sensors.

    Created for every channel input (IN1-IN8). In linked mode
    the value mirrors the relay — that's expected. In unlinked
    mode this is the only way to observe button presses.
    """

    _attr_has_entity_name = True

    def __init__(self, coordinator: HHCCoordinator, channel: int) -> None:
        super().__init__(coordinator)
        self._channel = channel
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, coordinator.device_id)},
            name=coordinator.device_name,
            manufacturer="HHC",
            model="N8I8OP",
            configuration_url=f"http://{coordinator.host}",
        )


class HHCGlobalInputEntity(CoordinatorEntity[HHCCoordinator]):
    """Base entity for global inputs (All On / All Off).

    The N8I8OP board has two additional optocoupler inputs:
      IN9  — All On:  hardware override that turns all relays on
      IN10 — All Off: hardware override that turns all relays off

    These are read from bits 9 and 10 of the 'input' response.
    They cannot be disabled via software — they bypass all link/mode settings.
    """

    _attr_has_entity_name = True

    def __init__(self, coordinator: HHCCoordinator) -> None:
        super().__init__(coordinator)
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, coordinator.device_id)},
            name=coordinator.device_name,
            manufacturer="HHC",
            model="N8I8OP",
            configuration_url=f"http://{coordinator.host}",
        )
