"""Tests for the Fail2ban metrics of the Telegraf provider."""

import json
import re
from datetime import timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from homeassistant.const import (
    CONF_SCAN_INTERVAL,
    CONF_URL,
    CONF_VERIFY_SSL,
    STATE_UNAVAILABLE,
    STATE_UNKNOWN,
)
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
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
    METRIC_FAIL2BAN_BANNED,
    METRIC_FAIL2BAN_BANNED_TOTAL,
    METRIC_FAIL2BAN_FAILED,
    METRIC_FAIL2BAN_FAILED_TOTAL,
    METRIC_LOAD_AVERAGE_1M,
    PROVIDER_NAME_GENERIC,
    PROVIDER_NAME_TELEGRAF,
)
from custom_components.openmetrics.metrics.processor import OpenMetricsProcessor
from custom_components.openmetrics.sensor import SENSORS, create_resource_sensors

from .helpers import (
    CONTENT_TYPE,
    FakeClock,
    get_metadata,
    load_fixture,
    poll,
    remove_samples,
    set_value,
)

HOST = "sweh00"
ALL = [
    METRIC_FAIL2BAN_BANNED,
    METRIC_FAIL2BAN_FAILED,
    METRIC_FAIL2BAN_BANNED_TOTAL,
    METRIC_FAIL2BAN_FAILED_TOTAL,
]
JAILS = {"adguardhome", "homeassistant", "postfix-sasl", "sshd"}


@pytest.fixture
def fail2ban() -> str:
    """Return the Fail2ban-only exposition."""
    return load_fixture("telegraf_fail2ban.prom")


def _data(text: str) -> dict:
    """Return the sensor data of all hosts for a single poll."""
    processor = OpenMetricsProcessor()
    get_metadata(text, processor)
    return poll(processor, text)


def _lines(text: str) -> str:
    """Return the sample lines of an exposition without comments."""
    return "\n".join(
        line for line in text.splitlines() if line and not line.startswith("#")
    )


def _sensor_ids(resource, metric_keys=ALL) -> set[str]:
    sensors = create_resource_sensors(resource, "h", MagicMock(), list(metric_keys))
    return {sensor.unique_id for sensor in sensors}


# Detection
def test_fail2ban_only_endpoint_is_detected_as_telegraf(fail2ban):
    """Both Fail2ban families are sufficient to detect Telegraf."""
    assert get_metadata(fail2ban).provider_info.name == PROVIDER_NAME_TELEGRAF


@pytest.mark.parametrize("family", ["fail2ban_banned", "fail2ban_failed"])
def test_single_fail2ban_family_is_not_detected(fail2ban, family):
    """A single Fail2ban family is not distinctive enough."""
    text = remove_samples(
        fail2ban,
        "fail2ban_failed" if family == "fail2ban_banned" else "fail2ban_banned",
    )
    assert get_metadata(text).provider_info.name != PROVIDER_NAME_TELEGRAF


def test_fail2ban_families_of_different_hosts_are_not_detected():
    """The combination has to be exposed by the same host."""
    text = 'fail2ban_banned{host="a",jail="sshd"} 1\nfail2ban_failed{host="b",jail="sshd"} 1\n'
    assert get_metadata(text).provider_info.name == PROVIDER_NAME_GENERIC


@pytest.mark.parametrize("missing", ["host", "jail"])
def test_fail2ban_samples_without_required_label_are_not_detected(missing):
    """Samples without host or jail label do not identify Telegraf."""
    labels = {"host": "a", "jail": "sshd"}
    del labels[missing]
    selector = ",".join(f'{k}="{v}"' for k, v in labels.items())
    text = f"fail2ban_banned{{{selector}}} 1\nfail2ban_failed{{{selector}}} 1\n"
    assert get_metadata(text).provider_info.name != PROVIDER_NAME_TELEGRAF


def test_fail2ban_counts_as_a_characteristic_family(sweh00, fail2ban):
    """Fail2ban is also taken into account for the generic family threshold."""
    text = (
        'system_load1{host="a"} 1\nfail2ban_banned{host="a",jail="s"} 1\n'
        'fail2ban_failed{host="a",jail="s"} 1\n'
    )
    assert get_metadata(text).provider_info.name == PROVIDER_NAME_TELEGRAF


# Discovery and availability
def test_discovers_jails_dynamically(fail2ban):
    """Jails are discovered at the host and no names are hardcoded."""
    metadata = get_metadata(fail2ban)
    resource = metadata.resources[HOST]
    assert set(metadata.resources) == {HOST}
    assert resource.jails == JAILS
    assert resource.jail_metrics == {
        jail: {METRIC_FAIL2BAN_BANNED, METRIC_FAIL2BAN_FAILED} for jail in JAILS
    }
    assert resource.available_metrics == set(ALL)
    assert metadata.available_metrics == ALL
    # Without network or filesystem metrics there are no such resources
    assert resource.network_interfaces is None
    assert resource.filesystems is None


def test_jails_of_multiple_hosts_and_identical_names():
    """Jails are assigned to their host, identical names do not interfere."""
    text = (
        'fail2ban_banned{host="a",jail="sshd"} 1\n'
        'fail2ban_failed{host="a",jail="sshd"} 2\n'
        'fail2ban_banned{host="a",jail="nginx"} 3\n'
        'fail2ban_failed{host="a",jail="nginx"} 4\n'
        'fail2ban_banned{host="b",jail="sshd"} 10\n'
        'fail2ban_failed{host="b",jail="sshd"} 20\n'
        'fail2ban_banned{host="b",jail="dovecot"} 30\n'
        'fail2ban_failed{host="b",jail="dovecot"} 40\n'
    )
    metadata = get_metadata(text)
    assert metadata.resources["a"].jails == {"sshd", "nginx"}
    assert metadata.resources["b"].jails == {"sshd", "dovecot"}
    data = _data(text)
    assert data["a"][f"{METRIC_FAIL2BAN_BANNED}_sshd"] == 1
    assert data["b"][f"{METRIC_FAIL2BAN_BANNED}_sshd"] == 10
    assert data["a"][METRIC_FAIL2BAN_BANNED_TOTAL] == 4
    assert data["a"][METRIC_FAIL2BAN_FAILED_TOTAL] == 6
    assert data["b"][METRIC_FAIL2BAN_BANNED_TOTAL] == 40
    assert data["b"][METRIC_FAIL2BAN_FAILED_TOTAL] == 60
    assert f"{METRIC_FAIL2BAN_BANNED}_dovecot" not in data["a"]
    assert f"{METRIC_FAIL2BAN_BANNED}_nginx" not in data["b"]


def test_asymmetric_jail_metrics():
    """Jails only get the sensors of the families they expose."""
    text = (
        'fail2ban_banned{host="a",jail="banned-only"} 1\n'
        'fail2ban_failed{host="a",jail="failed-only"} 2\n'
        'fail2ban_banned{host="a",jail="both"} 3\n'
        'fail2ban_failed{host="a",jail="both"} 4\n'
        'system_load1{host="a"} 1\nsystem_uptime{host="a"} 1000\n'
    )
    resource = get_metadata(text).resources["a"]
    assert resource.jail_metrics == {
        "banned-only": {METRIC_FAIL2BAN_BANNED},
        "failed-only": {METRIC_FAIL2BAN_FAILED},
        "both": {METRIC_FAIL2BAN_BANNED, METRIC_FAIL2BAN_FAILED},
    }
    # Totals require the metric from every jail
    assert METRIC_FAIL2BAN_BANNED_TOTAL not in resource.available_metrics
    assert METRIC_FAIL2BAN_FAILED_TOTAL not in resource.available_metrics
    assert _sensor_ids(resource) == {
        "h_a_fail2ban_banned_banned-only",
        "h_a_fail2ban_banned_both",
        "h_a_fail2ban_failed_failed-only",
        "h_a_fail2ban_failed_both",
    }


def test_missing_family_hides_its_sensors(fail2ban):
    """A missing metric family does not create (zero valued) sensors."""
    text = (
        remove_samples(fail2ban, "fail2ban_failed")
        + '\nsystem_load1{host="sweh00"} 1\nsystem_uptime{host="sweh00"} 1\n'
    )
    metadata = get_metadata(text)
    resource = metadata.resources[HOST]
    assert resource.available_metrics & set(ALL) == {
        METRIC_FAIL2BAN_BANNED,
        METRIC_FAIL2BAN_BANNED_TOTAL,
    }
    assert METRIC_LOAD_AVERAGE_1M in resource.available_metrics
    assert METRIC_FAIL2BAN_FAILED not in metadata.available_metrics
    assert METRIC_FAIL2BAN_FAILED_TOTAL not in metadata.available_metrics
    data = _data(text)[HOST]
    assert not [key for key in data if "failed" in key]
    assert data[METRIC_FAIL2BAN_BANNED_TOTAL] == 7


def test_samples_without_jail_or_host_create_no_jail_or_resource():
    """Samples missing a required label are ignored."""
    text = (
        'fail2ban_banned{host="a",jail="sshd"} 1\n'
        'fail2ban_failed{host="a",jail="sshd"} 1\n'
        'fail2ban_banned{host="a"} 5\n'
        'fail2ban_failed{host="a",jail=""} 5\n'
        'fail2ban_banned{jail="sshd"} 5\n'
        'fail2ban_failed{host="",jail="sshd"} 5\n'
    )
    metadata = get_metadata(text)
    assert set(metadata.resources) == {"a"}
    assert metadata.resources["a"].jails == {"sshd"}
    data = _data(text)["a"]
    assert data[METRIC_FAIL2BAN_BANNED_TOTAL] == 1
    assert data[METRIC_FAIL2BAN_FAILED_TOTAL] == 1


# Values
def test_values_and_totals(fail2ban):
    """Per-jail values and totals (sum over jails) are exposed as integers."""
    data = _data(fail2ban)[HOST]
    assert data == {
        f"{METRIC_FAIL2BAN_BANNED}_adguardhome": 0,
        f"{METRIC_FAIL2BAN_BANNED}_homeassistant": 0,
        f"{METRIC_FAIL2BAN_BANNED}_postfix-sasl": 2,
        f"{METRIC_FAIL2BAN_BANNED}_sshd": 5,
        f"{METRIC_FAIL2BAN_FAILED}_adguardhome": 0,
        f"{METRIC_FAIL2BAN_FAILED}_homeassistant": 0,
        f"{METRIC_FAIL2BAN_FAILED}_postfix-sasl": 1,
        f"{METRIC_FAIL2BAN_FAILED}_sshd": 3,
        METRIC_FAIL2BAN_BANNED_TOTAL: 7,
        METRIC_FAIL2BAN_FAILED_TOTAL: 4,
    }
    assert all(type(value) is int for value in data.values())


def test_total_is_a_sum_not_unique_addresses():
    """The same value in several jails is added up per jail."""
    text = (
        'fail2ban_banned{host="a",jail="x"} 3\nfail2ban_banned{host="a",jail="y"} 3\n'
        'fail2ban_failed{host="a",jail="x"} 1\nfail2ban_failed{host="a",jail="y"} 1\n'
    )
    assert _data(text)["a"][METRIC_FAIL2BAN_BANNED_TOTAL] == 6


def test_zero_values_are_valid(fail2ban):
    """Zero is a valid value, also for totals."""
    text = re.sub(r"\} \d+$", "} 0", fail2ban, flags=re.MULTILINE)
    data = _data(text)[HOST]
    assert data[METRIC_FAIL2BAN_BANNED_TOTAL] == 0
    assert data[METRIC_FAIL2BAN_FAILED_TOTAL] == 0
    assert data[f"{METRIC_FAIL2BAN_BANNED}_sshd"] == 0


@pytest.mark.parametrize(
    ("raw", "expected"), [("5e0", 5), ("1.2e+01", 12), ("7.0", 7), ("0.0", 0)]
)
def test_integral_values_in_float_notation(fail2ban, raw, expected):
    """Telegraf may emit integers in scientific or float notation."""
    text = set_value(fail2ban, 'fail2ban_banned{host="sweh00",jail="sshd"', raw)
    assert _data(text)[HOST][f"{METRIC_FAIL2BAN_BANNED}_sshd"] == expected


def test_values_may_rise_and_fall(fail2ban):
    """The gauges are exposed as they are, there are no rates or differences."""
    processor = OpenMetricsProcessor()
    get_metadata(fail2ban, processor)
    sshd = f"{METRIC_FAIL2BAN_BANNED}_sshd"
    totals = []
    for value in ("5", "50", "2", "0", "2"):
        text = set_value(fail2ban, 'fail2ban_banned{host="sweh00",jail="sshd"', value)
        data = poll(processor, text)[HOST]
        assert data[sshd] == int(value)
        totals.append(data[METRIC_FAIL2BAN_BANNED_TOTAL])
    assert totals == [7, 52, 4, 2, 4]


@pytest.mark.parametrize(
    "invalid", ["NaN", "+Inf", "-Inf", "-1", "-0.5", "1.5", "1e400"]
)
def test_invalid_values_are_not_exposed_and_hide_totals(fail2ban, invalid):
    """Invalid values are neither zero nor part of a partial sum."""
    text = set_value(fail2ban, 'fail2ban_banned{host="sweh00",jail="sshd"', invalid)
    data = _data(text)[HOST]
    assert f"{METRIC_FAIL2BAN_BANNED}_sshd" not in data
    assert METRIC_FAIL2BAN_BANNED_TOTAL not in data
    # Other jails and the failed family are not affected
    assert data[f"{METRIC_FAIL2BAN_BANNED}_postfix-sasl"] == 2
    assert data[METRIC_FAIL2BAN_FAILED_TOTAL] == 4
    assert data[f"{METRIC_FAIL2BAN_FAILED}_sshd"] == 3


def test_incomplete_family_at_runtime_hides_the_total(fail2ban):
    """A jail missing in one family leads to no misleading partial sum."""
    processor = OpenMetricsProcessor()
    get_metadata(fail2ban, processor)
    text = re.sub(
        r'^fail2ban_failed\{host="sweh00",jail="sshd"\}.*\n',
        "",
        fail2ban,
        flags=re.MULTILINE,
    )
    data = poll(processor, text)[HOST]
    assert METRIC_FAIL2BAN_FAILED_TOTAL not in data
    assert f"{METRIC_FAIL2BAN_FAILED}_sshd" not in data
    assert data[f"{METRIC_FAIL2BAN_FAILED}_postfix-sasl"] == 1
    assert data[METRIC_FAIL2BAN_BANNED_TOTAL] == 7


def test_missing_family_at_runtime_is_not_zero(fail2ban):
    """If a family disappears no values (and no zero totals) are exposed."""
    processor = OpenMetricsProcessor()
    get_metadata(fail2ban, processor)
    data = poll(processor, remove_samples(fail2ban, "fail2ban_failed"))[HOST]
    assert not [key for key in data if "failed" in key]
    assert data[METRIC_FAIL2BAN_BANNED_TOTAL] == 7


def test_duplicate_jail_sample_of_other_host_does_not_affect_totals():
    """Same jail on two hosts: invalid value only affects its own host."""
    text = (
        'fail2ban_banned{host="a",jail="sshd"} NaN\n'
        'fail2ban_failed{host="a",jail="sshd"} 1\n'
        'fail2ban_banned{host="b",jail="sshd"} 4\n'
        'fail2ban_failed{host="b",jail="sshd"} 5\n'
    )
    data = _data(text)
    assert METRIC_FAIL2BAN_BANNED_TOTAL not in data["a"]
    assert data["a"][METRIC_FAIL2BAN_FAILED_TOTAL] == 1
    assert data["b"][METRIC_FAIL2BAN_BANNED_TOTAL] == 4


# Independence of order, added and removed jails
def test_results_do_not_depend_on_the_order_of_the_families(fail2ban):
    """Reversed exposition gives the same metadata and values."""
    lines = _lines(fail2ban).splitlines()
    forward, backward = ("\n".join(order) + "\n" for order in (lines, lines[::-1]))
    meta_forward, meta_backward = get_metadata(forward), get_metadata(backward)
    assert meta_forward.available_metrics == meta_backward.available_metrics
    assert (
        meta_forward.resources[HOST].jail_metrics
        == meta_backward.resources[HOST].jail_metrics
    )
    assert _data(forward) == _data(backward)


def test_added_and_removed_jails(fail2ban):
    """Metadata follows the exposed jails, polls follow the current samples."""
    processor = OpenMetricsProcessor()
    get_metadata(fail2ban, processor)
    removed = fail2ban.replace('jail="sshd"', 'jail="sshd-removed"')
    removed = re.sub(r".*sshd-removed.*\n", "", removed)
    # Discovery of a new endpoint state
    assert get_metadata(removed).resources[HOST].jails == JAILS - {"sshd"}
    data = poll(processor, removed)[HOST]
    assert f"{METRIC_FAIL2BAN_BANNED}_sshd" not in data
    assert data[METRIC_FAIL2BAN_BANNED_TOTAL] == 2
    assert data[METRIC_FAIL2BAN_FAILED_TOTAL] == 1
    added = fail2ban + (
        'fail2ban_banned{host="sweh00",jail="nginx"} 9\n'
        'fail2ban_failed{host="sweh00",jail="nginx"} 8\n'
    )
    assert get_metadata(added).resources[HOST].jails == JAILS | {"nginx"}
    data = poll(processor, added)[HOST]
    assert data[f"{METRIC_FAIL2BAN_BANNED}_nginx"] == 9
    assert data[METRIC_FAIL2BAN_BANNED_TOTAL] == 16


# Existing sensors
def test_existing_telegraf_metrics_are_unchanged(sweh00, fail2ban):
    """Adding Fail2ban to an endpoint does not change the other sensors."""
    with patch(
        "custom_components.openmetrics.providers.telegraf.monotonic", FakeClock()
    ):
        before = _data(sweh00)[HOST]
        combined = sweh00 + "\n" + fail2ban
        after = _data(combined)[HOST]
    metadata = get_metadata(sweh00).resources[HOST]
    combined_metadata = get_metadata(combined).resources[HOST]
    fail2ban_keys = {k for k in after if k.startswith("fail2ban_")}
    assert fail2ban_keys
    assert {k: v for k, v in after.items() if k not in fail2ban_keys} == before
    assert combined_metadata.available_metrics == metadata.available_metrics | set(ALL)
    assert combined_metadata.network_interfaces == metadata.network_interfaces
    assert combined_metadata.filesystems == metadata.filesystems
    assert combined_metadata.jails == JAILS
    assert metadata.jails is None


def test_sensors_only_for_selected_metrics(fail2ban):
    """Per-jail and total sensors are selectable independently."""
    resource = get_metadata(fail2ban).resources[HOST]
    assert _sensor_ids(resource, [METRIC_FAIL2BAN_BANNED_TOTAL]) == {
        "h_sweh00_fail2ban_total_banned"
    }
    assert _sensor_ids(resource, [METRIC_FAIL2BAN_FAILED]) == {
        f"h_sweh00_fail2ban_failed_{jail}" for jail in JAILS
    }
    assert len(_sensor_ids(resource)) == 2 * len(JAILS) + 2
    assert _sensor_ids(resource, []) == set()


def test_sensor_descriptions():
    """All Fail2ban sensors use the same icon and a measurement state class."""
    for key in ALL:
        description = SENSORS[key]
        assert description.icon == "mdi:shield-lock-outline"
        assert description.state_class == "measurement"
        assert description.native_unit_of_measurement is None
        assert description.device_class is None


def test_jail_named_like_a_total_does_not_collide():
    """Jail sensors and total sensors have distinct unique IDs."""
    text = (
        'fail2ban_banned{host="a",jail="total"} 1\nfail2ban_failed{host="a",jail="total"} 1\n'
        'fail2ban_banned{host="a",jail="banned"} 2\nfail2ban_failed{host="a",jail="banned"} 2\n'
    )
    resource = get_metadata(text).resources["a"]
    ids = _sensor_ids(resource)
    assert len(ids) == 6
    data = _data(text)["a"]
    assert data[METRIC_FAIL2BAN_BANNED_TOTAL] == 3
    assert data[f"{METRIC_FAIL2BAN_BANNED}_total"] == 1


# Translations
@pytest.mark.parametrize(
    "path", ["strings.json", "translations/en.json", "translations/de.json"]
)
def test_translations(path):
    """Entity names and metric options exist for every Fail2ban metric."""
    root = Path(__file__).parent.parent / "custom_components" / "openmetrics"
    translations = json.loads((root / path).read_text(encoding="utf-8"))
    for key in ALL:
        assert translations["entity"]["sensor"][key]["name"]
        assert translations["selector"]["metrics"]["options"][key]
    for key in (METRIC_FAIL2BAN_BANNED, METRIC_FAIL2BAN_FAILED):
        assert "{jail}" in translations["entity"]["sensor"][key]["name"]
    for key in (METRIC_FAIL2BAN_BANNED_TOTAL, METRIC_FAIL2BAN_FAILED_TOTAL):
        assert "{" not in translations["entity"]["sensor"][key]["name"]


# Home Assistant integration
URL_HOST = "telegraf.local:9128"
REQUEST = "custom_components.openmetrics.client.OpenMetricsClient._async_request_data"


def _entry(metrics: list[str], resources: list[str]) -> MockConfigEntry:
    return MockConfigEntry(
        domain=DOMAIN,
        version=3,
        data={
            CONF_URL: f"http://{URL_HOST}/metrics",
            CONF_VERIFY_SSL: False,
            CONF_SCAN_INTERVAL: 10,
            CONF_RESOURCES: resources,
            CONF_METRICS: metrics,
        },
    )


def _state(hass: HomeAssistant, unique_id: str):
    entity_id = er.async_get(hass).async_get_entity_id("sensor", DOMAIN, unique_id)
    assert entity_id, unique_id
    return hass.states.get(entity_id)


async def _poll(hass: HomeAssistant, seconds: int) -> None:
    async_fire_time_changed(hass, dt_util.utcnow() + timedelta(seconds=seconds))
    await hass.async_block_till_done()


MULTI_HOST = (
    'fail2ban_banned{host="a",jail="sshd"} 1\n'
    'fail2ban_failed{host="a",jail="sshd"} 2\n'
    'fail2ban_banned{host="a",jail="nginx"} 3\n'
    'fail2ban_failed{host="a",jail="nginx"} 4\n'
    'fail2ban_banned{host="b",jail="sshd"} 10\n'
    'fail2ban_failed{host="b",jail="sshd"} 20\n'
    'system_load1{host="a"} 1\nsystem_load1{host="b"} 1\n'
)


async def test_fail2ban_entities(hass: HomeAssistant, fail2ban: str) -> None:
    """Jail and total sensors are created for the host device and updated."""
    entry = _entry(ALL, [HOST])
    entry.add_to_hass(hass)
    with patch(REQUEST, return_value=(fail2ban, CONTENT_TYPE)) as request:
        await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
        # One request for the metadata and one for the initial refresh
        assert request.call_count == 2
        registry = er.async_get(hass)
        entities = [
            e for e in registry.entities.values() if e.config_entry_id == entry.entry_id
        ]
        assert {e.unique_id for e in entities} == {
            f"{URL_HOST}_{HOST}_fail2ban_{kind}_{jail}"
            for kind in ("banned", "failed")
            for jail in JAILS
        } | {
            f"{URL_HOST}_{HOST}_fail2ban_total_banned",
            f"{URL_HOST}_{HOST}_fail2ban_total_failed",
        }
        # All entities belong to the host device
        device = dr.async_get(hass).async_get_device(
            identifiers={(DOMAIN, f"{URL_HOST}_{HOST}")}
        )
        assert device is not None
        assert {e.device_id for e in entities} == {device.id}

        prefix = f"{URL_HOST}_{HOST}_fail2ban_"
        sshd = _state(hass, f"{prefix}banned_sshd")
        assert sshd.state == "5"
        assert sshd.attributes["friendly_name"] == (
            "sweh00 Fail2ban – Currently banned (sshd)"
        )
        assert sshd.attributes["icon"] == "mdi:shield-lock-outline"
        assert sshd.attributes["state_class"] == "measurement"
        assert "unit_of_measurement" not in sshd.attributes
        assert _state(hass, f"{prefix}failed_postfix-sasl").state == "1"
        assert _state(hass, f"{prefix}failed_adguardhome").state == "0"
        total = _state(hass, f"{prefix}total_banned")
        assert total.state == "7"
        assert total.attributes["friendly_name"] == (
            "sweh00 Fail2ban – Currently banned (total)"
        )
        assert _state(hass, f"{prefix}total_failed").state == "4"

        # Values may fall and rise; one request per polling cycle
        for seconds, value, expected_total in ((11, "0", "2"), (22, "9", "11")):
            request.return_value = (
                set_value(fail2ban, 'fail2ban_banned{host="sweh00",jail="sshd"', value),
                CONTENT_TYPE,
            )
            before = request.call_count
            await _poll(hass, seconds)
            assert request.call_count == before + 1
            assert _state(hass, f"{prefix}banned_sshd").state == value
            assert _state(hass, f"{prefix}total_banned").state == expected_total

        # An invalid value makes the jail and the total unknown, never 0
        request.return_value = (
            set_value(fail2ban, 'fail2ban_banned{host="sweh00",jail="sshd"', "NaN"),
            CONTENT_TYPE,
        )
        await _poll(hass, 33)
        assert _state(hass, f"{prefix}banned_sshd").state == STATE_UNKNOWN
        assert _state(hass, f"{prefix}total_banned").state == STATE_UNKNOWN
        assert _state(hass, f"{prefix}failed_sshd").state == "3"

        # Outage and recovery
        request.side_effect = CannotConnectError("down")
        await _poll(hass, 44)
        assert _state(hass, f"{prefix}total_failed").state == STATE_UNAVAILABLE
        request.side_effect = None
        request.return_value = (fail2ban, CONTENT_TYPE)
        await _poll(hass, 55)
        assert _state(hass, f"{prefix}total_failed").state == "4"


async def test_fail2ban_multiple_hosts_with_identical_jail_names(
    hass: HomeAssistant,
) -> None:
    """The same jail on two hosts creates distinct entities per host device."""
    entry = _entry(ALL, ["a", "b"])
    entry.add_to_hass(hass)
    with patch(REQUEST, return_value=(MULTI_HOST, CONTENT_TYPE)):
        await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
    registry = er.async_get(hass)
    unique_ids = {e.unique_id for e in registry.entities.values()}
    prefix = f"{URL_HOST}_"
    assert f"{prefix}a_fail2ban_banned_sshd" in unique_ids
    assert f"{prefix}b_fail2ban_banned_sshd" in unique_ids
    assert f"{prefix}a_fail2ban_banned_nginx" in unique_ids
    assert f"{prefix}b_fail2ban_banned_nginx" not in unique_ids
    # host a: 2 jails x 2 + 2 totals, host b: 1 jail x 2 + 2 totals
    assert len(unique_ids) == 10
    entity_ids = {e.entity_id for e in registry.entities.values()}
    assert len(entity_ids) == len(unique_ids)
    assert _state(hass, f"{prefix}a_fail2ban_banned_sshd").state == "1"
    assert _state(hass, f"{prefix}b_fail2ban_banned_sshd").state == "10"
    assert _state(hass, f"{prefix}a_fail2ban_total_banned").state == "4"
    assert _state(hass, f"{prefix}b_fail2ban_total_banned").state == "10"


async def test_fail2ban_jails_follow_options_and_restart(
    hass: HomeAssistant, fail2ban: str
) -> None:
    """Selected metrics decide the sensors; IDs are stable across a reload."""
    entry = _entry([METRIC_FAIL2BAN_BANNED_TOTAL], [HOST])
    entry.add_to_hass(hass)
    with patch(REQUEST, return_value=(fail2ban, CONTENT_TYPE)):
        await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
        registry = er.async_get(hass)

        def ids() -> dict[str, str]:
            return {
                e.unique_id: e.entity_id
                for e in registry.entities.values()
                if e.config_entry_id == entry.entry_id
            }

        before = ids()
        assert set(before) == {f"{URL_HOST}_{HOST}_fail2ban_total_banned"}

        # The options flow offers the Fail2ban metrics and creates jail sensors
        result = await hass.config_entries.options.async_init(entry.entry_id)
        metrics = next(
            v for k, v in result["data_schema"].schema.items() if k == CONF_METRICS
        )
        assert set(ALL) <= set(metrics.config["options"])
        result = await hass.config_entries.options.async_configure(
            result["flow_id"],
            {
                CONF_RESOURCES: [HOST],
                CONF_METRICS: [METRIC_FAIL2BAN_BANNED_TOTAL, METRIC_FAIL2BAN_BANNED],
                CONF_SCAN_INTERVAL: 10,
            },
        )
        await hass.async_block_till_done()
        assert result["type"] is FlowResultType.CREATE_ENTRY
        after = ids()
        assert len(after) == 1 + len(JAILS)
        assert after.items() >= before.items()

        # Reload keeps the entity IDs
        await hass.config_entries.async_reload(entry.entry_id)
        await hass.async_block_till_done()
        assert ids() == after
