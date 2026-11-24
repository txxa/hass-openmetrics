"""Tests for unique IDs, entity IDs and registry stability."""

from unittest.mock import patch

from homeassistant.core import HomeAssistant, valid_entity_id
from homeassistant.helpers import entity_registry as er

from custom_components.openmetrics.const import DOMAIN

from .helpers import CONTENT_TYPE
from .test_integration import HOST, REQUEST, _entry

BASE = (
    'system_load1{host="a"} 1\nsystem_uptime{host="a"} 1\nsystem_n_cpus{host="a"} 1\n'
)
INTERFACES = ("wg-home", "wg_home", "wg.home", "WG-Home")
PATHS = ("/var/lib", "/var_lib", "/var-lib", "/var.lib")
METRICS = ["network_receive_bytes", "disk_usage_pct"]


def _text(reverse: bool = False) -> str:
    lines = [f'net_bytes_recv{{host="a",interface="{name}"}} 1' for name in INTERFACES]
    lines += [f'disk_used_percent{{host="a",path="{path}"}} 1' for path in PATHS]
    return BASE + "\n".join(lines[::-1] if reverse else lines) + "\n"


async def _setup(hass: HomeAssistant, text: str, entry=None):
    entry = entry or _entry(METRICS, ["a"])
    if entry.entry_id not in hass.config_entries._entries:  # noqa: SLF001
        entry.add_to_hass(hass)
    with patch(REQUEST, return_value=(text, CONTENT_TYPE)):
        await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
    return entry


def _mapping(hass: HomeAssistant) -> dict[str, str]:
    registry = er.async_get(hass)
    return {e.unique_id: e.entity_id for e in registry.entities.values()}


async def test_colliding_object_ids_stay_distinct_entities(hass: HomeAssistant):
    """Interfaces and paths with equal sanitized names get distinct entities."""
    await _setup(hass, _text())
    mapping = _mapping(hass)
    expected = {f"{HOST}_a_network_receive_bytes_{name}" for name in INTERFACES} | {
        f"{HOST}_a_disk_usage_pct_{path}" for path in PATHS
    }
    assert set(mapping) == expected
    assert len(set(mapping.values())) == len(mapping)
    assert all(valid_entity_id(entity_id) for entity_id in mapping.values())
    for entity_id in mapping.values():
        assert hass.states.get(entity_id) is not None


async def test_entity_ids_are_stable_across_reloads_and_restarts(hass: HomeAssistant):
    """Entity IDs and unique IDs are kept when the entry is reloaded or recreated."""
    entry = await _setup(hass, _text())
    before = _mapping(hass)
    # Reload of the entry
    with patch(REQUEST, return_value=(_text(), CONTENT_TYPE)):
        await hass.config_entries.async_reload(entry.entry_id)
        await hass.async_block_till_done()
    assert _mapping(hass) == before
    # Restart: registry is kept but the entities are set up in another order
    assert await hass.config_entries.async_unload(entry.entry_id)
    await hass.async_block_till_done()
    with patch(REQUEST, return_value=(_text(reverse=True), CONTENT_TYPE)):
        await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
    assert _mapping(hass) == before


async def test_existing_entity_ids_are_retained(hass: HomeAssistant):
    """Entities already in the registry keep their (renamed) entity ID."""
    registry = er.async_get(hass)
    entry = _entry(METRICS, ["a"])
    entry.add_to_hass(hass)
    unique_id = f"{HOST}_a_network_receive_bytes_wg-home"
    registry.async_get_or_create(
        "sensor",
        DOMAIN,
        unique_id,
        config_entry=entry,
        suggested_object_id="my_custom_name",
    )
    await _setup(hass, _text(), entry)
    mapping = _mapping(hass)
    assert mapping[unique_id] == "sensor.my_custom_name"
    # Another entity must not take over the free default ID of the renamed entity
    others = [v for k, v in mapping.items() if k != unique_id]
    assert "sensor.my_custom_name" not in others


async def test_unique_ids_of_existing_providers_are_unchanged(hass: HomeAssistant):
    """Node Exporter keeps its unique and entity IDs."""
    text = (
        'node_exporter_build_info{version="1.8.2"} 1\n'
        'node_uname_info{nodename="nas"} 1\n'
        'node_network_receive_bytes_total{device="eth0"} 100\n'
        'node_filesystem_size_bytes{device="/dev/sda1",mountpoint="/"} 100\n'
        'node_filesystem_free_bytes{device="/dev/sda1",mountpoint="/"} 40\n'
        "node_boot_time_seconds 1700000000\n"
    )
    entry = _entry(
        ["network_receive_bytes", "disk_usage_pct", "uptime_seconds"], ["nas"]
    )
    await _setup(hass, text, entry)
    mapping = _mapping(hass)
    assert set(mapping) == {
        f"{HOST}_nas_network_receive_bytes",
        f"{HOST}_nas_disk_usage_pct",
        f"{HOST}_nas_uptime_seconds",
    }
    assert mapping[f"{HOST}_nas_disk_usage_pct"] == (
        "sensor.telegraf_local_9128_nas_disk_usage_pct"
    )
