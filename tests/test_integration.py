"""Integration tests: Telegraf endpoint set up in Home Assistant."""

from datetime import timedelta
from unittest.mock import patch

from homeassistant.config_entries import ConfigEntryState
from homeassistant.const import (
    CONF_SCAN_INTERVAL,
    CONF_URL,
    CONF_VERIFY_SSL,
    STATE_UNAVAILABLE,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.util import dt as dt_util
from pytest_homeassistant_custom_component.common import (
    MockConfigEntry,
    async_fire_time_changed,
)

from custom_components.openmetrics.client import CannotConnectError
from custom_components.openmetrics.const import (
    CONF_METRICS,
    CONF_RESOURCES,
    DOMAIN,
)

from .helpers import CONTENT_TYPE, FakeClock, load_fixture, set_value

REQUEST = "custom_components.openmetrics.client.OpenMetricsClient._async_request_data"
CLOCK = "custom_components.openmetrics.providers.telegraf.monotonic"
HOST = "telegraf.local:9128"


def _entry(metrics: list[str], resources: list[str] | None = None) -> MockConfigEntry:
    return MockConfigEntry(
        domain=DOMAIN,
        version=3,
        data={
            CONF_URL: f"http://{HOST}/metrics",
            CONF_VERIFY_SSL: False,
            CONF_SCAN_INTERVAL: 10,
            CONF_RESOURCES: resources or ["sweh00"],
            CONF_METRICS: metrics,
        },
    )


def _state(hass: HomeAssistant, unique_id: str):
    registry = er.async_get(hass)
    entity_id = registry.async_get_entity_id("sensor", DOMAIN, unique_id)
    assert entity_id, unique_id
    return hass.states.get(entity_id)


async def test_telegraf_entities_and_updates(hass: HomeAssistant) -> None:
    """Entities are created, updated, become unavailable and recover."""
    text = load_fixture("telegraf_sweh00.prom")
    clock = FakeClock()
    all_metrics = [
        "cpu_usage_pct",
        "memory_usage_pct",
        "memory_usage_bytes",
        "swap_usage_pct",
        "swap_usage_bytes",
        "disk_usage_pct",
        "disk_usage_bytes",
        "network_receive_bytes",
        "network_transmit_bytes",
        "uptime_seconds",
        "load_average_1m",
        "load_average_5m",
        "load_average_15m",
    ]
    entry = _entry(all_metrics)
    entry.add_to_hass(hass)
    with (
        patch(CLOCK, clock),
        patch(REQUEST, return_value=(text, CONTENT_TYPE)) as request,
    ):
        await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
        assert entry.state is ConfigEntryState.LOADED
        # One request for the metadata and one for the initial refresh
        assert request.call_count == 2

        prefix = f"{HOST}_sweh00_"
        cpu = _state(hass, f"{prefix}cpu_usage_pct")
        assert (
            float(cpu.state) == round(100 - 68.23176823168284, 2)
            or abs(float(cpu.state) - 31.77) < 0.01
        )
        assert cpu.attributes["cpu_cores"] == 1
        assert float(_state(hass, f"{prefix}load_average_5m").state) == 0.38
        assert _state(hass, f"{prefix}disk_usage_pct_/tmp") is not None
        root = _state(hass, f"{prefix}disk_usage_pct_/")
        assert root.attributes["disk_device"] == "vda1"
        assert root.attributes["disk_size"] == "20 GB"
        # Network rate is not available before a second sample
        wg = _state(hass, f"{prefix}network_receive_bytes_wg-home")
        assert wg.state == "unknown"
        assert wg.entity_id.endswith("network_receive_bytes_wg_home")

        # Second poll: rates from counter differences and elapsed time
        clock.now += 5
        new_text = set_value(
            text, 'net_bytes_recv{host="sweh00",interface="wg-home"', "1.74172948e+08"
        )
        request.return_value = (new_text, CONTENT_TYPE)
        async_fire_time_changed(hass, dt_util.utcnow() + timedelta(seconds=11))
        await hass.async_block_till_done()
        wg = _state(hass, f"{prefix}network_receive_bytes_wg-home")
        # 500 bytes / 5 s = 100 B/s = 0.1 kB/s
        assert float(wg.state) == 0.1
        assert float(_state(hass, f"{prefix}network_receive_bytes_ethfe").state) == 0

        # Temporary failure: entities become unavailable
        request.side_effect = CannotConnectError("down")
        async_fire_time_changed(hass, dt_util.utcnow() + timedelta(seconds=22))
        await hass.async_block_till_done()
        assert _state(hass, f"{prefix}cpu_usage_pct").state == STATE_UNAVAILABLE

        # Recovery
        request.side_effect = None
        clock.now += 30
        async_fire_time_changed(hass, dt_util.utcnow() + timedelta(seconds=33))
        await hass.async_block_till_done()
        assert _state(hass, f"{prefix}cpu_usage_pct").state != STATE_UNAVAILABLE

    device = dr.async_get(hass).async_get_device(
        identifiers={(DOMAIN, f"{HOST}_sweh00")}
    )
    assert device is not None
    assert device.name == "sweh00"


async def test_only_selected_and_available_metrics_create_sensors(
    hass: HomeAssistant,
) -> None:
    """Sensors are only created for selected metrics available for the host."""
    text = load_fixture("telegraf_multi_host.prom")
    entry = _entry(
        ["swap_usage_pct", "load_average_1m", "load_average_5m"], ["alpha", "beta"]
    )
    entry.add_to_hass(hass)
    with patch(REQUEST, return_value=(text, CONTENT_TYPE)):
        await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
    registry = er.async_get(hass)
    unique_ids = {e.unique_id for e in registry.entities.values()}
    assert unique_ids == {
        f"{HOST}_beta_swap_usage_pct",
        f"{HOST}_alpha_load_average_1m",
        f"{HOST}_beta_load_average_1m",
    }
