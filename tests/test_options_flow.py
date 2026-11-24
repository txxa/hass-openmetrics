"""Tests for the options flow with a Telegraf endpoint."""

from datetime import timedelta
from unittest.mock import patch

from homeassistant.const import CONF_SCAN_INTERVAL
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er

from custom_components.openmetrics.client import CannotConnectError
from custom_components.openmetrics.const import CONF_METRICS, CONF_RESOURCES, DOMAIN

from .helpers import CONTENT_TYPE, load_fixture
from .test_integration import HOST, REQUEST, _entry


async def _setup(hass: HomeAssistant, resources, metrics):
    entry = _entry(metrics, resources)
    entry.add_to_hass(hass)
    await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    return entry


def _unique_ids(hass: HomeAssistant) -> set[str]:
    return {e.unique_id for e in er.async_get(hass).entities.values()}


def _devices(hass: HomeAssistant) -> set[str]:
    return {d.name for d in dr.async_get(hass).devices.values()}


async def _configure(hass: HomeAssistant, entry, user_input):
    result = await hass.config_entries.options.async_init(entry.entry_id)
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "init"
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], user_input
    )
    await hass.async_block_till_done()
    return result


async def test_options_offer_discovered_resources_and_metrics(hass: HomeAssistant):
    """The form offers the discovered hosts and only the available metrics."""
    text = load_fixture("telegraf_multi_host.prom")
    with patch(REQUEST, return_value=(text, CONTENT_TYPE)):
        entry = await _setup(hass, ["alpha"], ["cpu_usage_pct"])
        result = await hass.config_entries.options.async_init(entry.entry_id)
    schema = result["data_schema"].schema
    options = {key: key for key in schema}
    resources = next(v for k, v in schema.items() if k == CONF_RESOURCES)
    metrics = next(v for k, v in schema.items() if k == CONF_METRICS)
    assert options
    assert sorted(resources.config["options"]) == ["alpha", "beta"]
    assert "load_average_1m" in metrics.config["options"]
    assert "load_average_5m" not in metrics.config["options"]


async def test_options_change_resources_metrics_and_interval(hass: HomeAssistant):
    """Changing resources, metrics and scan interval updates entities and entry."""
    text = load_fixture("telegraf_multi_host.prom")
    with patch(REQUEST, return_value=(text, CONTENT_TYPE)):
        entry = await _setup(hass, ["alpha"], ["cpu_usage_pct", "load_average_1m"])
        assert _devices(hass) == {"alpha"}
        coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
        assert coordinator.update_interval == timedelta(seconds=10)

        # Add a host, add a metric and change the interval
        result = await _configure(
            hass,
            entry,
            {
                CONF_RESOURCES: ["alpha", "beta"],
                CONF_METRICS: ["cpu_usage_pct", "load_average_1m", "swap_usage_pct"],
                CONF_SCAN_INTERVAL: 30,
            },
        )
        assert result["type"] is FlowResultType.CREATE_ENTRY
        assert entry.data[CONF_RESOURCES] == ["alpha", "beta"]
        assert entry.data[CONF_SCAN_INTERVAL] == 30
        assert coordinator.update_interval == timedelta(seconds=30)
        assert _devices(hass) == {"alpha", "beta"}
        # alpha has no swap, so only beta gets the swap sensor
        assert _unique_ids(hass) == {
            f"{HOST}_alpha_cpu_usage_pct",
            f"{HOST}_alpha_load_average_1m",
            f"{HOST}_beta_cpu_usage_pct",
            f"{HOST}_beta_load_average_1m",
            f"{HOST}_beta_swap_usage_pct",
        }

        # Remove a host and metrics
        result = await _configure(
            hass,
            entry,
            {
                CONF_RESOURCES: ["beta"],
                CONF_METRICS: ["load_average_1m"],
                CONF_SCAN_INTERVAL: 5,
            },
        )
        assert result["type"] is FlowResultType.CREATE_ENTRY
        assert entry.data[CONF_METRICS] == ["load_average_1m"]
        assert coordinator.update_interval == timedelta(seconds=5)
        assert _devices(hass) == {"beta"}
        assert _unique_ids(hass) == {f"{HOST}_beta_load_average_1m"}


async def test_options_validation_errors(hass: HomeAssistant):
    """Empty selections are rejected and the entry is left untouched."""
    text = load_fixture("telegraf_multi_host.prom")
    with patch(REQUEST, return_value=(text, CONTENT_TYPE)):
        entry = await _setup(hass, ["alpha"], ["cpu_usage_pct"])
        result = await _configure(
            hass,
            entry,
            {
                CONF_RESOURCES: [],
                CONF_METRICS: ["cpu_usage_pct"],
                CONF_SCAN_INTERVAL: 10,
            },
        )
        assert result["errors"] == {"base": "no_resources"}
        result = await _configure(
            hass,
            entry,
            {CONF_RESOURCES: ["alpha"], CONF_METRICS: [], CONF_SCAN_INTERVAL: 10},
        )
        assert result["errors"] == {"base": "no_metrics"}
    assert entry.data[CONF_RESOURCES] == ["alpha"]
    assert entry.data[CONF_METRICS] == ["cpu_usage_pct"]


async def test_options_form_reports_connection_errors(hass: HomeAssistant):
    """An unreachable endpoint is reported in the options form."""
    text = load_fixture("telegraf_multi_host.prom")
    with patch(REQUEST, return_value=(text, CONTENT_TYPE)):
        entry = await _setup(hass, ["alpha"], ["cpu_usage_pct"])
    with patch(REQUEST, side_effect=CannotConnectError("down")):
        result = await hass.config_entries.options.async_init(entry.entry_id)
    assert result["errors"] == {"base": "cannot_connect"}
