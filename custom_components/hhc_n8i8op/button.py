"""Button platform for hhc-n8i8op — 'all on' and 'all off' commands.

These are momentary actions (commands), not toggle states.
Using ButtonEntity is correct: press = send command, no state to track.
"""

from __future__ import annotations

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import HHCCoordinator


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up all-on and all-off button entities."""
    coordinator: HHCCoordinator = entry.runtime_data  # type: ignore[assignment]
    async_add_entities([HHCAllOnButton(coordinator), HHCAllOffButton(coordinator)])


class HHCAllOnButton(CoordinatorEntity[HHCCoordinator], ButtonEntity):
    """Press to turn ALL relays ON simultaneously."""

    _attr_has_entity_name = True
    _attr_icon = "mdi:toggle-switch-variant"
    _attr_translation_key = "all_on"

    def __init__(self, coordinator: HHCCoordinator) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{coordinator.device_id}_all_on"
        self._attr_device_info = {
            "identifiers": {(DOMAIN, coordinator.device_id)},
        }

    async def async_press(self) -> None:
        """Send allon command."""
        await self.coordinator.set_all_on()


class HHCAllOffButton(CoordinatorEntity[HHCCoordinator], ButtonEntity):
    """Press to turn ALL relays OFF simultaneously."""

    _attr_has_entity_name = True
    _attr_icon = "mdi:toggle-switch-off"
    _attr_translation_key = "all_off"

    def __init__(self, coordinator: HHCCoordinator) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{coordinator.device_id}_all_off"
        self._attr_device_info = {
            "identifiers": {(DOMAIN, coordinator.device_id)},
        }

    async def async_press(self) -> None:
        """Send alloff command."""
        await self.coordinator.set_all_off()
