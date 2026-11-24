"""Polling, availability and recovery tests (existing providers and Telegraf)."""

import logging
from datetime import timedelta
from unittest.mock import patch

import pytest
from homeassistant.config_entries import ConfigEntryState
from homeassistant.const import STATE_UNAVAILABLE, STATE_UNKNOWN
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er
from homeassistant.util import dt as dt_util
from pytest_homeassistant_custom_component.common import async_fire_time_changed

from custom_components.openmetrics.client import CannotConnectError, RequestError
from custom_components.openmetrics.const import METRIC_UPTIME_SECONDS

from .helpers import CONTENT_TYPE, load_fixture
from .test_integration import HOST, REQUEST, _entry
from .test_regression_providers import NODE_EXPORTER

NODE_METRICS = ["memory_usage_pct", "disk_usage_pct", METRIC_UPTIME_SECONDS]
UNIQUE_ID = f"{HOST}_nas_memory_usage_pct"


async def _poll(hass: HomeAssistant, seconds: int) -> None:
    async_fire_time_changed(hass, dt_util.utcnow() + timedelta(seconds=seconds))
    await hass.async_block_till_done()


def _state(hass: HomeAssistant, unique_id: str) -> str:
    entity_id = er.async_get(hass).async_get_entity_id(
        "sensor", "openmetrics", unique_id
    )
    assert entity_id
    return hass.states.get(entity_id).state


@pytest.mark.parametrize(
    "error",
    [
        CannotConnectError("down"),
        RequestError("bad response"),
        ValueError("bad value"),
        RuntimeError("programming error"),
    ],
)
async def test_node_exporter_failure_and_recovery(hass: HomeAssistant, error, caplog):
    """Failures make entities unavailable and polling recovers automatically."""
    text = NODE_EXPORTER % {"idle": 100, "rx": 1000}
    entry = _entry(NODE_METRICS, ["nas"])
    entry.add_to_hass(hass)
    with patch(REQUEST, return_value=(text, CONTENT_TYPE)) as request:
        await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
        assert entry.state is ConfigEntryState.LOADED
        # Metadata request and initial refresh
        assert request.call_count == 2
        assert _state(hass, UNIQUE_ID) == "25.0"

        # Exactly one request per polling cycle
        await _poll(hass, 11)
        assert request.call_count == 3
        await _poll(hass, 22)
        assert request.call_count == 4

        # Failure: unavailable instead of a stale value
        request.side_effect = error
        await _poll(hass, 33)
        assert request.call_count == 5
        assert _state(hass, UNIQUE_ID) == STATE_UNAVAILABLE
        assert _state(hass, f"{HOST}_nas_uptime_seconds") == STATE_UNAVAILABLE
        assert "Error fetching openmetrics data" in caplog.text
        # The failure of a single cycle is retried with the next cycle
        await _poll(hass, 44)
        assert request.call_count == 6
        assert _state(hass, UNIQUE_ID) == STATE_UNAVAILABLE

        # Recovery
        request.side_effect = None
        await _poll(hass, 55)
        assert request.call_count == 7
        assert _state(hass, UNIQUE_ID) == "25.0"


async def test_unexpected_errors_are_logged_with_traceback(hass: HomeAssistant, caplog):
    """Programming errors are not masked: the traceback is logged."""
    text = NODE_EXPORTER % {"idle": 100, "rx": 1000}
    entry = _entry(NODE_METRICS, ["nas"])
    entry.add_to_hass(hass)
    with patch(REQUEST, return_value=(text, CONTENT_TYPE)) as request:
        await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
        request.side_effect = RuntimeError("programming error")
        with caplog.at_level(logging.ERROR):
            await _poll(hass, 11)
    records = [r for r in caplog.records if "Unexpected error" in r.getMessage()]
    assert records
    assert records[0].exc_info is not None
    assert "programming error" in caplog.text


async def test_telegraf_failure_and_recovery_keeps_network_baseline_valid(
    hass: HomeAssistant,
):
    """Telegraf entities become unavailable and recover after an outage."""
    text = load_fixture("telegraf_sweh00.prom")
    entry = _entry(["cpu_usage_pct", "load_average_1m"])
    entry.add_to_hass(hass)
    unique_id = f"{HOST}_sweh00_load_average_1m"
    with patch(REQUEST, return_value=(text, CONTENT_TYPE)) as request:
        await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
        assert _state(hass, unique_id) == "0.29"
        request.side_effect = CannotConnectError("down")
        await _poll(hass, 11)
        assert _state(hass, unique_id) == STATE_UNAVAILABLE
        request.side_effect = None
        await _poll(hass, 22)
        assert _state(hass, unique_id) == "0.29"


async def test_missing_metric_is_unknown_not_zero(hass: HomeAssistant):
    """A metric which disappears from the endpoint is not shown as 0."""
    text = load_fixture("telegraf_sweh00.prom")
    entry = _entry(["load_average_1m", "load_average_5m"])
    entry.add_to_hass(hass)
    with patch(REQUEST, return_value=(text, CONTENT_TYPE)) as request:
        await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
        request.return_value = (
            text.replace('system_load1{host="sweh00"} 0.29', ""),
            CONTENT_TYPE,
        )
        await _poll(hass, 11)
        assert _state(hass, f"{HOST}_sweh00_load_average_1m") in (
            STATE_UNKNOWN,
            STATE_UNAVAILABLE,
        )
        assert _state(hass, f"{HOST}_sweh00_load_average_5m") == "0.38"
