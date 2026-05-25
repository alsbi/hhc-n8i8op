"""Switch platform for hhc-n8i8op relay channels."""

from __future__ import annotations

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import CHANNEL_TYPE_LIGHT, OPT_CHANNEL_TYPES
from .coordinator import HHCCoordinator
from .entity import HHCEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up switch entities for channels configured as 'switch'."""
    coordinator: HHCCoordinator = entry.runtime_data  # type: ignore[assignment]
    channel_types: dict[str, str] = entry.options.get(OPT_CHANNEL_TYPES, {})

    entities: list[HHCSwitchEntity] = []

    for ch in range(coordinator.channel_count):
        if channel_types.get(str(ch), "switch") != CHANNEL_TYPE_LIGHT:
            entities.append(HHCSwitchEntity(coordinator, ch))

    async_add_entities(entities)


class HHCSwitchEntity(HHCEntity, SwitchEntity):
    """A single relay channel exposed as a switch."""

    def __init__(self, coordinator: HHCCoordinator, channel: int) -> None:
        super().__init__(coordinator, channel)
        self._attr_unique_id = f"{coordinator.device_id}_ch{channel + 1}_switch"
        self._attr_name = f"Channel {channel + 1}"

    @property
    def is_on(self) -> bool | None:
        """Return true if the relay is on."""
        return self.relay_is_on

    async def async_turn_on(self, **kwargs: object) -> None:
        """Turn the relay on."""
        await self.async_turn_relay_on()

    async def async_turn_off(self, **kwargs: object) -> None:
        """Turn the relay off."""
        await self.async_turn_relay_off()
