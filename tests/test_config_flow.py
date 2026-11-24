"""Tests for the config flow with a Telegraf endpoint."""

from unittest.mock import patch

from homeassistant import config_entries
from homeassistant.const import CONF_SCAN_INTERVAL, CONF_URL, CONF_VERIFY_SSL
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType

from custom_components.openmetrics.client import CannotConnectError
from custom_components.openmetrics.const import (
    CONF_METRICS,
    CONF_RESOURCES,
    DOMAIN,
    METRIC_LOAD_AVERAGE_1M,
    METRIC_SWAP_USAGE_PCT,
)

from .helpers import CONTENT_TYPE, load_fixture

URL = "http://10.250.0.1:9128/metrics"
REQUEST = "custom_components.openmetrics.client.OpenMetricsClient._async_request_data"
SETUP = "custom_components.openmetrics.async_setup_entry"


async def _start_flow(hass: HomeAssistant, fixture: str):
    with patch(REQUEST, return_value=(load_fixture(fixture), CONTENT_TYPE)):
        result = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": config_entries.SOURCE_USER}
        )
        return await hass.config_entries.flow.async_configure(
            result["flow_id"], {CONF_URL: URL, CONF_VERIFY_SSL: False}
        )


async def test_flow_discovers_telegraf_resources(hass: HomeAssistant) -> None:
    """The Telegraf endpoint can be configured without 'No resources selected'."""
    result = await _start_flow(hass, "telegraf_sweh00.prom")
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "resources"
    options = result["data_schema"].schema[CONF_RESOURCES].config["options"]
    assert options == ["sweh00"]

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_RESOURCES: ["sweh00"]}
    )
    assert result["step_id"] == "metrics"
    options = result["data_schema"].schema[CONF_METRICS].config["options"]
    assert METRIC_LOAD_AVERAGE_1M in options
    assert METRIC_SWAP_USAGE_PCT in options

    with patch(SETUP, return_value=True):
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {CONF_METRICS: options}
        )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == "10.250.0.1:9128 (Telegraf)"
    assert result["data"][CONF_RESOURCES] == ["sweh00"]
    assert result["data"][CONF_METRICS] == options
    assert result["data"][CONF_SCAN_INTERVAL] == 10


async def test_flow_lists_all_hosts(hass: HomeAssistant) -> None:
    """All hosts of a multi host endpoint can be selected."""
    result = await _start_flow(hass, "telegraf_multi_host.prom")
    options = result["data_schema"].schema[CONF_RESOURCES].config["options"]
    assert sorted(options) == ["alpha", "beta"]

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_RESOURCES: []}
    )
    assert result["errors"] == {"base": "no_resources"}


async def test_flow_cannot_connect(hass: HomeAssistant) -> None:
    """Connection errors are reported."""
    with patch(REQUEST, side_effect=CannotConnectError("boom")):
        result = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": config_entries.SOURCE_USER}
        )
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {CONF_URL: URL, CONF_VERIFY_SSL: False}
        )
    assert result["errors"] == {"base": "cannot_connect"}
