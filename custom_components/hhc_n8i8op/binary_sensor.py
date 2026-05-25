"""Binary sensor platform for hhc-n8i8op input channels.

Creates binary sensors for:
  - ALL 8 per-channel inputs (IN1–IN8)
  - 2 global inputs: IN9 (All On) and IN10 (All Off)

In linked mode channel input values mirror the relay (expected).
In unlinked mode they are the only way to observe button presses.
Global inputs are hardware overrides that bypass all link/mode settings.
"""

from __future__ import annotations

from homeassistant.components.binary_sensor import BinarySensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .coordinator import HHCCoordinator
from .entity import HHCGlobalInputEntity, HHCInputEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up binary sensor entities for all inputs + global inputs."""
    coordinator: HHCCoordinator = entry.runtime_data  # type: ignore[assignment]

    entities: list[HHCInputBinarySensor | HHCGlobalBinarySensor] = []

    # Per-channel inputs (IN1-IN8)
    for ch in range(coordinator.channel_count):
        entities.append(HHCInputBinarySensor(coordinator, ch))

    # Global inputs (IN9 = All On, IN10 = All Off)
    entities.append(HHCGlobalOnSensor(coordinator))
    entities.append(HHCGlobalOffSensor(coordinator))

    async_add_entities(entities)


class HHCInputBinarySensor(HHCInputEntity, BinarySensorEntity):
    """A physical input channel exposed as a binary sensor.

    Created for every channel. In linked mode the value will match
    the corresponding switch/light — that's expected and harmless.
    In unlinked mode this is the only way to observe button presses.
    """

    def __init__(self, coordinator: HHCCoordinator, channel: int) -> None:
        super().__init__(coordinator, channel)
        self._attr_unique_id = f"{coordinator.device_id}_input_{channel + 1}"
        self._attr_name = f"Input {channel + 1}"

    @property
    def available(self) -> bool:
        """Return True if coordinator has input data for this channel."""
        return (
            self.coordinator.last_update_success
            and self.coordinator.data is not None
            and len(self.coordinator.data.inputs) > self._channel
        )

    @property
    def is_on(self) -> bool | None:
        """Return true if the physical input is active."""
        if (
            self.coordinator.data is None
            or not self.coordinator.data.inputs
            or len(self.coordinator.data.inputs) <= self._channel
        ):
            return None
        return self.coordinator.data.inputs[self._channel]

    @property
    def extra_state_attributes(self) -> dict[str, str]:
        """Return input mode and linked channel reference."""
        return {
            "input_mode": self.coordinator.get_input_mode(),
            "linked_channel": str(self._channel + 1),
        }


class HHCGlobalBinarySensor(HHCGlobalInputEntity, BinarySensorEntity):
    """Base class for global input binary sensors (IN9/IN10)."""

    _attr_entity_category = EntityCategory.DIAGNOSTIC


class HHCGlobalOnSensor(HHCGlobalBinarySensor):
    """IN9 — All On global input.

    When active, hardware forces ALL relays on simultaneously.
    This bypasses all software link/mode settings — it's a physical override.
    """

    _attr_translation_key = "global_input_all_on"

    def __init__(self, coordinator: HHCCoordinator) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{coordinator.device_id}_global_input_all_on"

    @property
    def available(self) -> bool:
        return (
            self.coordinator.last_update_success and self.coordinator.data is not None
        )

    @property
    def is_on(self) -> bool | None:
        if self.coordinator.data is None:
            return None
        return self.coordinator.data.global_on

    @property
    def extra_state_attributes(self) -> dict[str, str]:
        return {
            "input_number": "9",
            "type": "global_hardware_override",
        }


class HHCGlobalOffSensor(HHCGlobalBinarySensor):
    """IN10 — All Off global input.

    When active, hardware forces ALL relays off simultaneously.
    This bypasses all software link/mode settings — it's a physical override.
    """

    _attr_translation_key = "global_input_all_off"

    def __init__(self, coordinator: HHCCoordinator) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{coordinator.device_id}_global_input_all_off"

    @property
    def available(self) -> bool:
        return (
            self.coordinator.last_update_success and self.coordinator.data is not None
        )

    @property
    def is_on(self) -> bool | None:
        if self.coordinator.data is None:
            return None
        return self.coordinator.data.global_off

    @property
    def extra_state_attributes(self) -> dict[str, str]:
        return {
            "input_number": "10",
            "type": "global_hardware_override",
        }
