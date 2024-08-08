"""Options flow for openmetrics integration."""

import logging
from datetime import timedelta
from typing import Any

import aiohttp
import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import (
    CONF_PASSWORD,
    CONF_SCAN_INTERVAL,
    CONF_URL,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
)
from homeassistant.data_entry_flow import FlowResult
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.selector import selector

from .client import CannotConnectError, InvalidAuthError, OpenMetricsClient
from .const import CONF_RESOURCES, DOMAIN
from .coordinator import OpenMetricsDataUpdateCoordinator
from .sensor import create_resource_sensors

_LOGGER = logging.getLogger(__name__)


class OpenMetricsOptionsFlowHandler(config_entries.OptionsFlow):
    """Options flow handler for the OpenMetrics integration."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        """Initialize options flow."""
        self.config_entry = config_entry
        self.client = self._create_client(dict(config_entry.data))
        self.metadata = {}

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Manage the options."""
        errors: dict[str, str] = {}
        configured_resources = self.config_entry.data[CONF_RESOURCES]
        configured_scan_interval = self.config_entry.data[CONF_SCAN_INTERVAL]
        # Process user input if available
        if user_input is not None:
            try:
                # Validate input
                config_input = self._validate_input(user_input)
                # Update resources
                await self._async_update_resources(config_input[CONF_RESOURCES])
                # Update scan interval
                self._update_scan_interval(config_input[CONF_SCAN_INTERVAL])
                # Set entry data
                data = self.config_entry.data.copy()
                data[CONF_RESOURCES] = config_input[CONF_RESOURCES]
                data[CONF_SCAN_INTERVAL] = config_input[CONF_SCAN_INTERVAL]
                # Update entry
                self.hass.config_entries.async_update_entry(
                    self.config_entry, data=data, options=self.config_entry.options
                )
                return self.async_create_entry(title=None, data={})
            except ResourcesError as e:
                _LOGGER.error("Resources error: %s", str(e))
                errors["base"] = "no_resources"
            except ValueError as e:
                _LOGGER.error("Invalid input: %s", str(e))
                errors["base"] = "invalid_input"
            except Exception:
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"
            finally:
                configured_resources = user_input[CONF_RESOURCES]
                configured_scan_interval = user_input[CONF_SCAN_INTERVAL]
        # Define data schema
        try:
            available_resources = await self._async_get_available_resources()
        except CannotConnectError as e:
            _LOGGER.error("Failed to connect: %s", str(e))
            errors["base"] = "cannot_connect"
        except InvalidAuthError as e:
            _LOGGER.error("Authentication failed: %s", str(e))
            errors["base"] = "invalid_auth"
        data_schema = vol.Schema(
            {
                vol.Required(
                    CONF_RESOURCES, default=vol.Coerce(list)(configured_resources)
                ): selector(
                    {
                        "select": {
                            "options": available_resources,
                            "multiple": True,
                            "mode": "list",
                        }
                    }
                ),
                vol.Required(
                    CONF_SCAN_INTERVAL,
                    default=vol.Coerce(int)(configured_scan_interval),
                ): selector(
                    {
                        "number": {
                            "mode": "box",
                            "min": 1,
                            "max": 60,
                            "step": 1,
                        }
                    }
                ),
            },
            extra=vol.ALLOW_EXTRA,
        )
        # Show form
        return self.async_show_form(
            step_id="init",
            data_schema=data_schema,
            errors=errors,
        )

    def _validate_input(self, data: dict[str, Any]) -> dict[str, Any]:
        """Process user input and create new or update existing config entry."""
        resources = data.get(CONF_RESOURCES, [])
        scan_interval = data.get(CONF_SCAN_INTERVAL)
        if len(resources) == 0:
            raise ResourcesError("No resources selected")
        if scan_interval is None or not isinstance(scan_interval, (float, int)):
            raise ValueError("Invalid or missing scan interval")
        return {
            CONF_RESOURCES: resources,
            CONF_SCAN_INTERVAL: scan_interval,
        }

    async def _async_update_resources(self, new_resources: list[str]) -> None:
        """Update the resources, adding new ones and removing unselected ones."""
        # Remove unselected resources
        removed_resources = []
        for resource in self.config_entry.data[CONF_RESOURCES]:
            if resource not in new_resources:
                removed = await self._async_remove_resource_from_hass(resource)
                if removed:
                    removed_resources.append(resource)
        if removed_resources:
            _LOGGER.info("Removed resources %s from Home Assistant", removed_resources)
        # Add new resources
        added_resources = []
        for resource in new_resources:
            if resource not in self.config_entry.data[CONF_RESOURCES]:
                added = await self._async_add_resource_to_hass(resource)
                if added:
                    added_resources.append(resource)
        if added_resources:
            _LOGGER.info("Added resources %s to Home Assistant", added_resources)

    def _update_scan_interval(self, new_scan_interval: int) -> None:
        """Update the scan interval if it has changed."""
        current_scan_interval = int(self.config_entry.data[CONF_SCAN_INTERVAL])
        if new_scan_interval != current_scan_interval:
            for coordinator in self.hass.data[DOMAIN][self.config_entry.entry_id][
                "coordinators"
            ].values():
                coordinator.update_interval = timedelta(seconds=new_scan_interval)
            _LOGGER.info("Updated update interval to %s seconds", new_scan_interval)

    def _create_client(self, data: dict[str, Any]) -> OpenMetricsClient:
        """Create a new OpenMetricsClient instance."""
        url = data[CONF_URL]
        username = data.get(CONF_USERNAME)
        password = data.get(CONF_PASSWORD)
        verify_ssl = data[CONF_VERIFY_SSL]
        return OpenMetricsClient(url, verify_ssl, username, password)

    async def _async_remove_resource_from_hass(self, resource_name: str) -> bool:
        """Remove a resource from Home Assistant."""
        device_registry = self.hass.data[dr.DATA_REGISTRY]
        device_entries = device_registry.devices.data.copy()
        for device_entry in device_entries.values():
            for config_entry in device_entry.config_entries:
                if (
                    config_entry == self.config_entry.entry_id
                    and device_entry.name == resource_name
                ):
                    # Remove coordinator
                    if (
                        resource_name
                        in self.hass.data[DOMAIN][self.config_entry.entry_id][
                            "coordinators"
                        ]
                    ):
                        self.hass.data[DOMAIN][self.config_entry.entry_id][
                            "coordinators"
                        ].pop(device_entry.name)
                    else:
                        _LOGGER.debug(
                            "Coordinator for resource %s not found", resource_name
                        )
                    # Remove device including its entities
                    device_registry.async_remove_device(device_entry.id)
                    _LOGGER.debug(
                        "Removed device registry entry: %s.%s", DOMAIN, resource_name
                    )
                    return True
        return False

    async def _async_add_resource_to_hass(self, resource_name: str) -> bool:
        """Add a resource to Home Assistant."""
        device_registry = self.hass.data[dr.DATA_REGISTRY]
        for resource in self.metadata.get("resources", []):
            if resource["name"] == resource_name:
                platform = None
                # Find platform
                platforms = self.hass.data["entity_platform"][DOMAIN]
                for pltf in platforms:
                    if pltf.config_entry.entry_id == self.config_entry.entry_id:
                        platform = pltf
                        break
                if platform is None:
                    _LOGGER.error(
                        "No platform found for config entry %s",
                        self.config_entry.entry_id,
                    )
                    return False
                # Create coordinator
                coordinator = OpenMetricsDataUpdateCoordinator(
                    self.hass,
                    client=self.client,
                    resources=[resource_name],
                    update_interval=int(self.config_entry.data[CONF_SCAN_INTERVAL]),
                )
                # Create sensors
                sensors = create_resource_sensors(
                    self.hass,
                    self.config_entry,
                    resource,
                    coordinator,
                )
                # Register device
                device_entry = device_registry.async_get_or_create(
                    config_entry_id=self.config_entry.entry_id,
                    name=sensors[0].device_info["name"],
                    model=sensors[0].device_info["model"],
                    manufacturer=sensors[0].device_info["manufacturer"],
                    sw_version=sensors[0].device_info["sw_version"],
                    identifiers=sensors[0].device_info["identifiers"],
                    entry_type=sensors[0].device_info["entry_type"],
                )
                # Link sensors to device
                for sensor in sensors:
                    sensor.device_entry = device_entry
                # Add sensors to hass
                await platform.async_add_entities(sensors)
                # Add coordinator to config entry
                self.hass.data[DOMAIN][self.config_entry.entry_id]["coordinators"][
                    resource["name"]
                ] = coordinator
                return True
        return False

    async def _async_get_available_resources(self) -> list[str]:
        """Process user input and create new or update existing config entry."""
        try:
            # Get metadata
            self.metadata = await self.client.get_metadata()
            # Get available resources
            resources = [
                resource["name"] for resource in self.metadata.get("resources", [])
            ]
        except aiohttp.ClientError as e:
            raise CannotConnectError(str(e)) from e
        else:
            return resources


class ResourcesError(HomeAssistantError):
    """Error to indicate issues related to resources."""
