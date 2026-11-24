"""Coordinator for OpenMetrics."""

import logging
from datetime import timedelta

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import (
    DataUpdateCoordinator,
    UpdateFailed,
)

from custom_components.openmetrics.metrics.data import ResourceInfoData

from .client import (
    CannotConnectError,
    ClientError,
    InvalidAuthError,
    OpenMetricsClient,
    RequestError,
)
from .const import (
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)


class OpenMetricsDataUpdateCoordinator(DataUpdateCoordinator):
    """Define an object to manage OpenMetrics data update coordination."""

    def __init__(
        self,
        hass: HomeAssistant,
        client: OpenMetricsClient,
        resources: dict[str, ResourceInfoData],
        update_interval: int,
    ) -> None:
        """Initialize the data update coordinator."""
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=update_interval),
        )
        self._client = client
        self.resources = resources
        self.network_interfaces = None

    async def _async_update_data(self):
        """Fetch OpenMetrics data.

        Failures are raised as UpdateFailed instead of being logged while returning
        None. Home Assistant then marks the entities as unavailable (instead of
        showing a stale "unknown" state), logs the outage only once and retries
        with the regular scan interval until the endpoint recovers.
        """
        try:
            _LOGGER.debug(
                "Started fetching %s data from %s", self.name, self._client.url
            )
            # Get metrics
            metrics = await self._client.get_metrics(list(self.resources.keys()))
            # Process metrics for sensors
            sensor_data = self._client.process_metrics(metrics, self.update_interval)
        except CannotConnectError as e:
            raise UpdateFailed(f"Failed to connect: {e}") from e
        except InvalidAuthError as e:
            raise UpdateFailed(f"Authentication failed: {e}") from e
        except RequestError as e:
            raise UpdateFailed(f"Resources error: {e}") from e
        except ClientError as e:
            raise UpdateFailed(f"Processing error: {e}") from e
        except ValueError as e:
            raise UpdateFailed(f"Value error: {e}") from e
        except Exception as e:
            # UpdateFailed is logged without a traceback, so keep it for bugs
            _LOGGER.exception("Unexpected error while updating %s data", self.name)
            raise UpdateFailed(f"Unexpected error: {e}") from e
        else:
            # Return sensor data
            return sensor_data
