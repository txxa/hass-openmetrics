"""Config flow for openmetrics integration."""

from __future__ import annotations

import logging
import urllib.parse
from typing import Any

import aiohttp
import voluptuous as vol
from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.const import (
    CONF_PASSWORD,
    CONF_SCAN_INTERVAL,
    CONF_URL,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
)
from homeassistant.core import callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.selector import selector

from .client import (
    CannotConnectError,
    InvalidAuthError,
    OpenMetricsClient,
    ProcessingError,
    RequestError,
)
from .const import (
    CONF_METRICS,
    CONF_RESOURCES,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    METRICS_CADVISOR,
    METRICS_NODE_EXPORTER,
    PROVIDER_NAME_CADVISOR,
    PROVIDER_NAME_NODE_EXPORTER,
)
from .options_flow import OpenMetricsOptionsFlowHandler

_LOGGER = logging.getLogger(__name__)


STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_URL): str,
        vol.Optional(CONF_USERNAME): str,
        vol.Optional(CONF_PASSWORD): str,
        vol.Optional(CONF_VERIFY_SSL, default=vol.Coerce(bool)(False)): bool,
    }
)


class OpenMetricsConfigFlowHandler(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for openmetrics."""

    VERSION = 1
    title: str
    data: dict[str, Any]
    metadata: dict[str, Any]

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}
        # Process user input if provided
        if user_input is not None:
            try:
                # Check if an entry already exists with the same host
                for entry in self._async_current_entries():
                    if entry.data[CONF_URL] == user_input[CONF_URL]:
                        return self.async_abort(reason="already_configured")
                # Validate input
                self.data, self.metadata = await self._async_validate_user_step_input(
                    user_input
                )
                # Extract provider info
                if "provider" in self.metadata:
                    provider_name = self.metadata["provider"]["name"]
                    provider_version = self.metadata["provider"]["version"]
                # Define entry title
                host = urllib.parse.urlparse(user_input[CONF_URL]).netloc
                self.title = (
                    f"{provider_name} metrics (host={host}, version={provider_version})"
                )
                # Show config form
                return await self.async_step_config()
            except CannotConnectError as e:
                _LOGGER.error("Failed to connect: %s", str(e))
                errors["base"] = "cannot_connect"
            except InvalidAuthError as e:
                _LOGGER.error("Authentication failed: %s", str(e))
                errors["base"] = "invalid_auth"
            except RequestError as e:
                _LOGGER.error("Request error: %s", str(e))
                errors["base"] = "request_error"
            except ProcessingError as e:
                _LOGGER.error("Processing error: %s", str(e))
                errors["base"] = "processing_error"
            except ResourcesError as e:
                _LOGGER.error("Resources error: %s", str(e))
                errors["base"] = "no_resources"
            except Exception:
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"
        return self.async_show_form(
            step_id="user", data_schema=STEP_USER_DATA_SCHEMA, errors=errors
        )

    async def _async_validate_user_step_input(self, data: dict[str, Any]) -> tuple:
        """Process user input and create new or update existing config entry."""
        try:
            url = data[CONF_URL]
            username = data.get(CONF_USERNAME)
            password = data.get(CONF_PASSWORD)
            verify_ssl = data[CONF_VERIFY_SSL]
            # Create client
            client = OpenMetricsClient(url, verify_ssl, username, password)
            # Get metadata
            response = await client.get_metadata()
            # Define entry data
            self.data = data
        except aiohttp.ClientError as e:
            raise e from CannotConnectError
        else:
            return (data, response)

    async def async_step_config(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}
        # Process user input if provided
        if user_input is not None:
            try:
                # Validate input
                config_input = self._validate_config_step_input(user_input)
                # Set entry data
                self.data[CONF_METRICS] = config_input[CONF_METRICS]
                self.data[CONF_RESOURCES] = config_input[CONF_RESOURCES]
                self.data[CONF_SCAN_INTERVAL] = config_input[CONF_SCAN_INTERVAL]
                # Create entry
                return self.async_create_entry(title=self.title, data=self.data)
            except ProviderError as e:
                _LOGGER.error("Provider error: %s", str(e))
                errors["base"] = "invalid_provider"
            except ResourcesError as e:
                _LOGGER.error("Resources error: %s", str(e))
                errors["base"] = "no_resources"
            except ValueError as e:
                _LOGGER.error("Invalid input: %s", str(e))
                errors["base"] = "invalid_input"
        # Define data schema
        resources = [
            resource["name"] for resource in self.metadata.get("resources", [])
        ]
        data_schema = vol.Schema(
            {
                vol.Required(CONF_RESOURCES, default=vol.Coerce(list)([])): selector(
                    {
                        "select": {
                            "options": resources,
                            "multiple": True,
                            "mode": "list",
                        }
                    }
                ),
                vol.Required(
                    CONF_SCAN_INTERVAL, default=vol.Coerce(int)(DEFAULT_SCAN_INTERVAL)
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
            step_id="config",
            data_schema=data_schema,
            errors=errors,
        )

    def _validate_config_step_input(self, data: dict[str, Any]) -> dict[str, Any]:
        """Process user input and create new or update existing config entry."""
        metrics = {}
        resources = data[CONF_RESOURCES]
        scan_interval = data[CONF_SCAN_INTERVAL]

        if "provider" in self.metadata:
            provider_name = self.metadata["provider"]["name"]
            if provider_name == PROVIDER_NAME_NODE_EXPORTER:
                metrics = METRICS_NODE_EXPORTER
            elif provider_name == PROVIDER_NAME_CADVISOR:
                metrics = METRICS_CADVISOR
            else:
                raise ProviderError(f"Provider '{provider_name}' not supported")
        else:
            raise ProviderError("No provider info")
        if len(resources) == 0:
            raise ResourcesError("No resources selected")
        if scan_interval < 1:
            raise ValueError("Scan interval must be at least 1 second")
        return {
            CONF_METRICS: metrics,
            CONF_RESOURCES: resources,
            CONF_SCAN_INTERVAL: scan_interval,
        }

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        """Get the options flow for this handler."""
        return OpenMetricsOptionsFlowHandler(config_entry)


class ResourcesError(HomeAssistantError):
    """Error to indicate issues related to resources."""


class ProviderError(HomeAssistantError):
    """Error to indicate issues related to the metrics provider."""
