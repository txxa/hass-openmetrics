"""The openmetrics integration."""

from __future__ import annotations

import logging
import urllib.parse

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    CONF_PASSWORD,
    CONF_RESOURCES,
    CONF_SCAN_INTERVAL,
    CONF_URL,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
    Platform,
)
from homeassistant.core import HomeAssistant

from .client import (
    CannotConnectError,
    InvalidAuthError,
    OpenMetricsClient,
    ProcessingError,
    RequestError,
)
from .const import DOMAIN
from .coordinator import OpenMetricsDataUpdateCoordinator

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.SENSOR]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up openmetrics from a config entry."""
    try:
        hass.data.setdefault(DOMAIN, {})
        # Extract entry data
        url = entry.data[CONF_URL]
        username = entry.data.get(CONF_USERNAME)
        password = entry.data.get(CONF_PASSWORD)
        verify_ssl = entry.data[CONF_VERIFY_SSL]
        # Create an instance of the OpenMetricsClient
        client = OpenMetricsClient(url, verify_ssl, username, password)
        # Validate the OpenMetrics connection (and authentication)
        metadata = await client.get_metadata()
        # Create domain data if it does not exist
        if DOMAIN not in hass.data:
            hass.data[DOMAIN] = {}
        # Filter metadata of configured resources
        resources = []
        coordinators = {}
        for resource in metadata["resources"]:
            if resource["name"] in entry.data[CONF_RESOURCES]:
                resources.append(resource)
                coordinator = OpenMetricsDataUpdateCoordinator(
                    hass,
                    client=client,
                    resources=[resource["name"]],
                    update_interval=int(entry.data[CONF_SCAN_INTERVAL]),
                )
                coordinators[resource["name"]] = coordinator
        # Get the host name from the URL
        host = urllib.parse.urlparse(url).netloc
        # Store required entry data in hass domain entry object
        hass.data[DOMAIN][entry.entry_id] = {
            "client": client,
            "resources": resources,
            "coordinators": coordinators,
            "host": host,
        }
        # Forward the setup to your platforms, passing the coordinator to them
        for platform in PLATFORMS:
            hass.async_create_task(
                hass.config_entries.async_forward_entry_setup(entry, platform)
            )
    except CannotConnectError as e:
        _LOGGER.error("Failed to connect: %s", str(e))
        return False
    except InvalidAuthError as e:
        _LOGGER.error("Authentication failed: %s", str(e))
        return False
    except RequestError as e:
        _LOGGER.error("Resources error: %s", str(e))
        return False
    except ProcessingError as e:
        _LOGGER.error("Processing error: %s", str(e))
        return False
    except ValueError as e:
        _LOGGER.error("Value error: %s", str(e))
        return False
    except Exception:
        _LOGGER.exception("Unexpected exception")
        return False
    else:
        return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)


async def async_migrate_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    """Migrate old entry."""
    _LOGGER.debug(
        "Migrating configuration from version %s.%s",
        config_entry.version,
        config_entry.minor_version,
    )

    # Extract the connection data from the config entry
    url = config_entry.data[CONF_URL]
    username = config_entry.data.get(CONF_USERNAME)
    password = config_entry.data.get(CONF_PASSWORD)
    verify_ssl = config_entry.data[CONF_VERIFY_SSL]

    # Get metaadata of the configured OpenMetrics provider
    client = OpenMetricsClient(url, verify_ssl, username, password)
    metadata = await client.get_metadata()

    # Skip migration if not needed
    if config_entry.version > 1:
        # This means the user has downgraded from a future version
        return False

    # Version 1 migration
    if config_entry.version == 1:
        version = 1
        new_data = {**config_entry.data}
        if config_entry.minor_version < 1:
            minor_version = 1
            # Extract the available metrics based on the metadata
            available_metrics = metadata["metrics"]
            # Prepare new data for the config entry
            new_data["resources"] = [config_entry.data[CONF_RESOURCES]]
            new_data["metrics"] = available_metrics
            new_data["scan_interval"] = config_entry.data[CONF_SCAN_INTERVAL]

        hass.config_entries.async_update_entry(
            config_entry, data=new_data, version=version, minor_version=minor_version
        )
        _LOGGER.debug(
            "Migration to configuration version %s.%s successful",
            config_entry.version,
            config_entry.minor_version,
        )

    return True
