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
    Platform,
)
from homeassistant.data_entry_flow import FlowResult
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.device_registry import DeviceEntry
from homeassistant.helpers.entity_platform import EntityPlatform
from homeassistant.helpers.selector import (
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
    selector,
)

from .client import CannotConnectError, InvalidAuthError, OpenMetricsClient
from .const import (
    CONF_METRICS,
    CONF_RESOURCES,
    CONTAINER_METRICS,
    DOMAIN,
    NODE_METRICS,
    PROVIDER_NAME_CADVISOR,
    PROVIDER_NAME_NODE_EXPORTER,
)
from .coordinator import OpenMetricsDataUpdateCoordinator
from .sensor import SENSORS, create_resource_sensors, create_sensor

_LOGGER = logging.getLogger(__name__)


class OpenMetricsOptionsFlowHandler(config_entries.OptionsFlow):
    """Options flow handler for the OpenMetrics integration."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        """Initialize options flow."""
        self.config_entry = config_entry
        self.client = self._create_client(dict(config_entry.data))
        self.metadata = {}

    def _get_available_resources(self, resources) -> list[str]:
        """Get available resources from the metadata."""
        return [resource["name"] for resource in resources]

    def _get_available_metrics(self, provider_name) -> list[str]:
        """Get available metrics for a provider."""
        provider_metrics = {}
        if provider_name == PROVIDER_NAME_CADVISOR:
            provider_metrics = CONTAINER_METRICS
        if provider_name == PROVIDER_NAME_NODE_EXPORTER:
            provider_metrics = NODE_METRICS
        return list(dict.fromkeys(provider_metrics))

    def _get_platform(self, type: str) -> EntityPlatform:
        platforms = self.hass.data["entity_platform"][DOMAIN]
        for platform in platforms:
            if (
                platform.config_entry.entry_id == self.config_entry.entry_id
                and platform.domain == type
            ):
                return platform
        _LOGGER.error(
            "No platform found for config entry %s",
            self.config_entry.entry_id,
        )
        raise HomeAssistantError(
            "No platform found for config entry %s",
            self.config_entry.entry_id,
        )

    def _get_integration_device_entries(self) -> list[DeviceEntry]:
        """Get device entries for the config entry."""
        device_entries = []
        device_registry = self.hass.data[dr.DATA_REGISTRY]
        for device_entry in device_registry.devices.data.values():
            for config_entry in device_entry.config_entries:
                if config_entry == self.config_entry.entry_id:
                    device_entries.append(device_entry)
                    break
        if len(device_entries) == 0:
            _LOGGER.error(
                "No devices found for config entry %s",
                self.config_entry.entry_id,
            )
        return device_entries

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Manage the options."""
        errors: dict[str, str] = {}
        configured_resources = self.config_entry.data[CONF_RESOURCES]
        configured_metrics = list(dict.fromkeys(self.config_entry.data[CONF_METRICS]))
        configured_scan_interval = self.config_entry.data[CONF_SCAN_INTERVAL]
        self.sensor_platform = self._get_platform(Platform.SENSOR)
        # Process user input if available
        if user_input is not None:
            try:
                # Validate input
                config_input = self._validate_input(user_input)
                # Update resources
                await self._async_update_resources(config_input[CONF_RESOURCES])
                # Update metrics
                await self._async_update_metrics(config_input[CONF_METRICS])
                # Update scan interval
                self._update_scan_interval(config_input[CONF_SCAN_INTERVAL])
                # Set entry data
                data = self.config_entry.data.copy()
                data[CONF_RESOURCES] = config_input[CONF_RESOURCES]
                data[CONF_METRICS] = list(dict.fromkeys(config_input[CONF_METRICS]))
                data[CONF_SCAN_INTERVAL] = config_input[CONF_SCAN_INTERVAL]
                # Update entry
                self.hass.config_entries.async_update_entry(
                    self.config_entry, data=data, options=self.config_entry.options
                )
                return self.async_create_entry(title=None, data={})
            except ResourcesError as e:
                _LOGGER.error("Resources error: %s", str(e))
                errors["base"] = "no_resources"
            except MetricsError as e:
                _LOGGER.error("Metrics error: %s", str(e))
                errors["base"] = "no_metrics"
            except ValueError as e:
                _LOGGER.error("Invalid input: %s", str(e))
                errors["base"] = "invalid_input"
            except Exception:
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"
            finally:
                configured_resources = user_input[CONF_RESOURCES]
                configured_metrics = user_input[CONF_METRICS]
                configured_scan_interval = user_input[CONF_SCAN_INTERVAL]
        # Define data schema
        try:
            self.metadata = await self._async_get_metadata()
            available_resources = self._get_available_resources(
                self.metadata.get("resources", [])
            )
            available_metrics = self._get_available_metrics(
                self.metadata["provider"]["name"]
            )
        except CannotConnectError as e:
            _LOGGER.error("Failed to connect: %s", str(e))
            errors["base"] = "cannot_connect"
        except InvalidAuthError as e:
            _LOGGER.error("Authentication failed: %s", str(e))
            errors["base"] = "invalid_auth"
        data_schema = vol.Schema(
            {
                vol.Required(
                    CONF_RESOURCES,
                    description={"suggested_value": configured_resources},
                ): SelectSelector(
                    SelectSelectorConfig(
                        options=available_resources,
                        translation_key=CONF_METRICS,
                        multiple=True,
                        mode=SelectSelectorMode.LIST,
                    )
                ),
                vol.Required(
                    CONF_METRICS,
                    description={"suggested_value": configured_metrics},
                ): SelectSelector(
                    SelectSelectorConfig(
                        options=available_metrics,
                        translation_key=CONF_METRICS,
                        multiple=True,
                        mode=SelectSelectorMode.LIST,
                    )
                ),
                vol.Required(
                    CONF_SCAN_INTERVAL,
                    # default=vol.Coerce(int)(configured_scan_interval),
                    description={"suggested_value": configured_scan_interval},
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
        metrics = data.get(CONF_METRICS, [])
        scan_interval = data.get(CONF_SCAN_INTERVAL)
        if len(resources) == 0:
            raise ResourcesError("No resources selected")
        if len(metrics) == 0:
            raise MetricsError("No metrics selected")
        if scan_interval is None or not isinstance(scan_interval, (float, int)):
            raise ValueError("Invalid or missing scan interval")
        return {
            CONF_RESOURCES: resources,
            CONF_METRICS: metrics,
            CONF_SCAN_INTERVAL: scan_interval,
        }

    async def _async_update_resources(self, resources: list[str]) -> None:
        """Update the resources, adding new ones and removing unselected ones."""
        # Remove unselected resources
        removed_resources = []
        device_entries = self._get_integration_device_entries()
        for device in device_entries:
            for resource in self.config_entry.data[CONF_RESOURCES]:
                if resource not in resources:
                    removed = await self._async_remove_resource_from_hass(
                        device, resource
                    )
                    if removed:
                        removed_resources.append(resource)
            if removed_resources:
                _LOGGER.info(
                    "Removed resources %s from Home Assistant", removed_resources
                )
        # Add new resources
        added_resources = []
        for resource in resources:
            if resource not in self.config_entry.data[CONF_RESOURCES]:
                added = await self._async_add_resource_to_hass(resource)
                if added:
                    added_resources.append(resource)
        if added_resources:
            _LOGGER.info("Added resources %s to Home Assistant", added_resources)

    async def _async_update_metrics(self, metrics: list[str]) -> None:
        """Update the metrics, adding new ones and removing unselected ones."""
        device_entries = self._get_integration_device_entries()
        for device in device_entries:
            # Remove unselected metrics
            removed_metrics = []
            for metric in self.config_entry.data[CONF_METRICS]:
                if metric not in metrics:
                    removed = await self._async_remove_entity_from_device(
                        device, metric
                    )
                    if removed:
                        removed_metrics.append(metric)
            if removed_metrics:
                _LOGGER.info(
                    "Removed metrics %s from device '%s'", removed_metrics, device.name
                )
            # Add new metrics
            added_metrics = []
            for metric in metrics:
                if metric not in self.config_entry.data[CONF_METRICS]:
                    added = await self._async_add_entity_to_device(device, metric)
                    if added:
                        added_metrics.append(metric)
            if added_metrics:
                _LOGGER.info(
                    "Added metrics %s to device '%s'", added_metrics, device.name
                )

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

    async def _async_remove_resource_from_hass(
        self, device: DeviceEntry, resource_name: str
    ) -> bool:
        """Remove a resource from Home Assistant."""
        device_registry = self.hass.data[dr.DATA_REGISTRY]
        # for device in device_registry.devices.data.values():
        for config_entry in device.config_entries:
            if (
                config_entry == self.config_entry.entry_id
                and device.name == resource_name
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
                    ].pop(device.name)
                else:
                    _LOGGER.debug(
                        "Coordinator for resource %s not found", resource_name
                    )
                # Remove device including its entities
                device_registry.async_remove_device(device.id)
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
                await self.sensor_platform.async_add_entities(sensors)
                # Add coordinator to config entry
                self.hass.data[DOMAIN][self.config_entry.entry_id]["coordinators"][
                    resource["name"]
                ] = coordinator
                # Add resource to config entry
                self.hass.data[DOMAIN][self.config_entry.entry_id]["resources"].append(
                    resource
                )
                return True
        return False

    async def _async_add_entity_to_device(
        self, device_entry: DeviceEntry, metric_key: str
    ) -> bool:
        """Add an entity to a device."""
        sensors = []
        host = self.hass.data[DOMAIN][self.config_entry.entry_id]["host"]
        resources = self.hass.data[DOMAIN][self.config_entry.entry_id]["resources"]
        coordinators = self.hass.data[DOMAIN][self.config_entry.entry_id][
            "coordinators"
        ]
        # Create sensors
        for resource in resources:
            if resource["name"] == device_entry.name:
                coordinator = coordinators[resource["name"]]
                for key, description in SENSORS.items():
                    if key == metric_key:
                        sensor = create_sensor(resource, coordinator, description, host)
                        sensor.device_entry = device_entry
                        sensors.append(sensor)
        if len(sensors) == 0:
            _LOGGER.error(
                "No sensors found for config entry %s",
                self.config_entry.entry_id,
            )
            return False
        # Add sensors to hass
        await self.sensor_platform.async_add_entities(sensors)
        return True

    async def _async_remove_entity_from_device(
        self, device: DeviceEntry, metric_key: str
    ) -> bool:
        """Remove an entity from a device."""
        entity_registry = self.hass.data[er.DATA_REGISTRY]
        for entity_entry in entity_registry.entities.data.values():
            if (
                entity_entry.config_entry_id == self.config_entry.entry_id
                and entity_entry.device_id == device.id
                and entity_entry.translation_key == metric_key
            ):
                # Remove entity
                entity_registry.async_remove(entity_entry.entity_id)
                return True
        return False

    async def _async_enable_metric_of_device(
        self, device: DeviceEntry, metric_key: str
    ) -> bool:
        """Enable a metric."""
        entity_registry = self.hass.data[er.DATA_REGISTRY]
        for entity_entry in entity_registry.entities.data.values():
            if (
                entity_entry.config_entry_id == self.config_entry.entry_id
                and entity_entry.device_id == device.id
                and entity_entry.translation_key == metric_key
            ):
                # Enable metric
                entity_registry.async_update_entity(
                    entity_entry.entity_id, disabled_by=None
                )
                return True
        return False

    async def _async_disable_metric_of_device(
        self, device: DeviceEntry, metric_key: str
    ) -> bool:
        """Disable a metric."""
        entity_registry = self.hass.data[er.DATA_REGISTRY]
        for entity_entry in entity_registry.entities.data.values():
            if (
                entity_entry.config_entry_id == self.config_entry.entry_id
                and entity_entry.device_id == device.id
                and entity_entry.translation_key == metric_key
            ):
                # Disable metric
                entity_registry.async_update_entity(
                    entity_entry.entity_id, disabled_by=er.RegistryEntryDisabler.USER
                )
                return True
        return False

    async def _async_get_metadata(self) -> dict:
        """Get metadata from OpenMetrics provider."""
        try:
            # Get metadata
            metadata = await self.client.get_metadata()
        except aiohttp.ClientError as e:
            raise CannotConnectError(str(e)) from e
        else:
            return metadata


class MetricsError(HomeAssistantError):
    """Error to indicate issues related to metrics."""


class ResourcesError(HomeAssistantError):
    """Error to indicate issues related to resources."""
