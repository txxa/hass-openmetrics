"""Tests for the Telegraf metadata: availability, detection and label handling."""

from unittest.mock import MagicMock

import pytest

from custom_components.openmetrics.const import (
    METRIC_DISK_USAGE_BYTES,
    METRIC_DISK_USAGE_PCT,
    METRIC_MEMORY_USAGE_BYTES,
    METRIC_MEMORY_USAGE_PCT,
    METRIC_NETWORK_RECEIVE_BYTES,
    METRIC_NETWORK_TRANSMIT_BYTES,
    METRIC_SWAP_USAGE_BYTES,
    METRIC_SWAP_USAGE_PCT,
    PROVIDER_NAME_CADVISOR,
    PROVIDER_NAME_GENERIC,
    PROVIDER_NAME_NODE_EXPORTER,
    PROVIDER_NAME_TELEGRAF,
)
from custom_components.openmetrics.sensor import create_resource_sensors

from .helpers import get_metadata

# Detection of the provider needs some additional host level families
BASE = (
    'system_load1{host="a"} 1\nsystem_uptime{host="a"} 1\nsystem_n_cpus{host="a"} 1\n'
)


def _both_orders(text: str) -> list:
    """Extract the metadata with the lines in original and reversed order."""
    lines = text.strip().splitlines()
    return [get_metadata("\n".join(order) + "\n") for order in (lines, lines[::-1])]


# Availability is evaluated per host
def test_complementary_memory_families_of_different_hosts_are_not_combined():
    """mem_total of one host and mem_available of another do not enable memory."""
    text = BASE + 'mem_total{host="a"} 1e9\nmem_available{host="b"} 5e8\n'
    for metadata in _both_orders(text):
        assert METRIC_MEMORY_USAGE_PCT not in metadata.available_metrics
        assert METRIC_MEMORY_USAGE_BYTES not in metadata.available_metrics
        for resource in metadata.resources.values():
            assert METRIC_MEMORY_USAGE_PCT not in resource.available_metrics


def test_complete_memory_family_of_a_single_host_is_advertised():
    """Memory is advertised as soon as one host can calculate it."""
    text = (
        BASE
        + 'mem_total{host="a"} 1e9\nmem_available{host="b"} 5e8\n'
        + 'mem_total{host="b"} 1e9\n'
    )
    for metadata in _both_orders(text):
        assert METRIC_MEMORY_USAGE_PCT in metadata.available_metrics
        assert METRIC_MEMORY_USAGE_BYTES in metadata.available_metrics
        assert METRIC_MEMORY_USAGE_PCT not in metadata.resources["a"].available_metrics
        assert METRIC_MEMORY_USAGE_PCT in metadata.resources["b"].available_metrics


def test_swap_is_evaluated_per_host():
    """Unconfigured swap of one host does not hide or enable swap of another."""
    text = (
        BASE
        + 'swap_total{host="a"} 0\nswap_used{host="a"} 0\n'
        + 'swap_total{host="b"} 2e9\nswap_used{host="c"} 1e9\n'
    )
    for metadata in _both_orders(text):
        resources = metadata.resources
        assert not {METRIC_SWAP_USAGE_BYTES, METRIC_SWAP_USAGE_PCT} & (
            resources["a"].available_metrics
        )
        # swap_total without usage cannot be used
        assert not {METRIC_SWAP_USAGE_BYTES, METRIC_SWAP_USAGE_PCT} & (
            resources["b"].available_metrics
        )
        assert METRIC_SWAP_USAGE_BYTES in resources["c"].available_metrics
        assert METRIC_SWAP_USAGE_PCT not in resources["c"].available_metrics
        assert METRIC_SWAP_USAGE_BYTES in metadata.available_metrics
        assert METRIC_SWAP_USAGE_PCT not in metadata.available_metrics


def test_unconfigured_swap_is_hidden_independent_of_family_order():
    """swap_used before or after swap_total=0 gives the same result."""
    for text in (
        BASE + 'swap_used{host="a"} 0\nswap_total{host="a"} 0\n',
        BASE + 'swap_total{host="a"} 0\nswap_used{host="a"} 0\n',
    ):
        metadata = get_metadata(text)
        assert METRIC_SWAP_USAGE_BYTES not in metadata.available_metrics
        assert METRIC_SWAP_USAGE_PCT not in metadata.available_metrics


def test_metric_availability_does_not_depend_on_family_order(sweh00, multi_host):
    """Reversing the exposition does not change the advertised metrics."""
    for text in (sweh00, multi_host):
        lines = [line for line in text.splitlines() if not line.startswith("#")]
        forward = get_metadata("\n".join(lines) + "\n")
        backward = get_metadata("\n".join(lines[::-1]) + "\n")
        assert forward.available_metrics == backward.available_metrics
        assert {
            name: res.available_metrics for name, res in forward.resources.items()
        } == {name: res.available_metrics for name, res in backward.resources.items()}


# Availability per interface and filesystem
def _sensor_ids(resource, metric_keys):
    coordinator = MagicMock()
    sensors = create_resource_sensors(resource, "host", coordinator, metric_keys)
    return {sensor.unique_id for sensor in sensors}


def test_asymmetric_interface_metrics():
    """RX only and TX only interfaces only get the matching sensor."""
    text = (
        BASE
        + 'net_bytes_recv{host="a",interface="rx-only"} 1\n'
        + 'net_bytes_sent{host="a",interface="tx-only"} 1\n'
        + 'net_bytes_recv{host="a",interface="both"} 1\n'
        + 'net_bytes_sent{host="a",interface="both"} 1\n'
    )
    resource = get_metadata(text).resources["a"]
    assert resource.network_interfaces == {"rx-only", "tx-only", "both"}
    assert resource.interface_metrics == {
        "rx-only": {METRIC_NETWORK_RECEIVE_BYTES},
        "tx-only": {METRIC_NETWORK_TRANSMIT_BYTES},
        "both": {METRIC_NETWORK_RECEIVE_BYTES, METRIC_NETWORK_TRANSMIT_BYTES},
    }
    unique_ids = _sensor_ids(
        resource, [METRIC_NETWORK_RECEIVE_BYTES, METRIC_NETWORK_TRANSMIT_BYTES]
    )
    assert unique_ids == {
        "host_a_network_receive_bytes_rx-only",
        "host_a_network_transmit_bytes_tx-only",
        "host_a_network_receive_bytes_both",
        "host_a_network_transmit_bytes_both",
    }


def test_asymmetric_filesystem_metrics():
    """Required families must exist for the same mount point."""
    text = (
        BASE
        + 'disk_used_percent{host="a",path="/pct"} 1\n'
        # Total of one mount point cannot be combined with free of another
        + 'disk_total{host="a",path="/total"} 1e9\n'
        + 'disk_free{host="a",path="/free"} 1e9\n'
        + 'disk_total{host="a",path="/both"} 1e9\n'
        + 'disk_free{host="a",path="/both"} 1e9\n'
        + 'disk_used{host="a",path="/used"} 1e9\n'
    )
    resource = get_metadata(text).resources["a"]
    assert resource.filesystem_metrics == {
        "/pct": {METRIC_DISK_USAGE_PCT},
        "/total": set(),
        "/free": set(),
        "/both": {METRIC_DISK_USAGE_PCT, METRIC_DISK_USAGE_BYTES},
        "/used": {METRIC_DISK_USAGE_BYTES},
    }
    unique_ids = _sensor_ids(resource, [METRIC_DISK_USAGE_PCT, METRIC_DISK_USAGE_BYTES])
    assert unique_ids == {
        "host_a_disk_usage_pct_/pct",
        "host_a_disk_usage_pct_/both",
        "host_a_disk_usage_bytes_/both",
        "host_a_disk_usage_bytes_/used",
    }


def test_resources_without_per_identity_metadata_are_unrestricted(sweh00):
    """Providers not providing per interface metadata keep creating all sensors."""
    resource = get_metadata(sweh00).resources["sweh00"]
    resource.interface_metrics = None
    resource.filesystem_metrics = None
    unique_ids = _sensor_ids(resource, [METRIC_NETWORK_RECEIVE_BYTES])
    assert len(unique_ids) == 3


# Labels
@pytest.mark.parametrize(
    "line",
    [
        'disk_used_percent{host="x"} 1',
        'disk_used_percent{host="x",path=""} 1',
        'net_bytes_recv{host="x"} 1',
        'net_bytes_recv{host="x",interface=""} 1',
        'cpu_usage_idle{host="x"} 1',
        'mem_used{host=""} 1',
        'mem_used{instance="x"} 1',
    ],
)
def test_samples_missing_required_labels_do_not_create_resources(line):
    """Invalid samples neither create resources nor interfaces/filesystems."""
    metadata = get_metadata(BASE + line + "\n")
    assert list(metadata.resources) == ["a"]
    resource = metadata.resources["a"]
    assert not resource.network_interfaces
    assert not resource.filesystems


def test_invalid_samples_do_not_hide_valid_ones():
    """Valid samples of the same family are still used."""
    text = (
        BASE
        + 'net_bytes_recv{host="a"} 1\n'
        + 'net_bytes_recv{host="a",interface="eth0"} 1\n'
    )
    resource = get_metadata(text).resources["a"]
    assert resource.network_interfaces == {"eth0"}


def test_label_of_another_family_does_not_create_filesystems():
    """A path label on a host family does not create a filesystem."""
    text = BASE + 'mem_total{host="a",path="/"} 1\n'
    resource = get_metadata(text).resources["a"]
    assert not resource.filesystems


# Detection of minimal configurations
@pytest.mark.parametrize(
    "text",
    [
        # Network only
        'net_bytes_recv{host="a",interface="eth0"} 1\n'
        'net_bytes_sent{host="a",interface="eth0"} 1\n',
        # Memory only
        'mem_used_percent{host="a"} 1\nmem_total{host="a"} 1\n',
        'mem_used_percent{host="a"} 1\nmem_used{host="a"} 1\n'
        'mem_total{host="a"} 1\nmem_available{host="a"} 1\n',
        # Swap only
        'swap_used_percent{host="a"} 1\nswap_total{host="a"} 1\n',
        # Disk only
        'disk_used_percent{host="a",path="/"} 1\ndisk_total{host="a",path="/"} 1\n',
    ],
)
def test_minimal_configurations_are_detected(text):
    """Endpoints exposing only a few input plugins are detected."""
    assert get_metadata(text).provider_info.name == PROVIDER_NAME_TELEGRAF


@pytest.mark.parametrize(
    "text",
    [
        # Single family
        'net_bytes_recv{host="a",interface="eth0"} 1\n',
        'system_load1{host="a"} 1\n',
        # Families without common combination
        'mem_total{host="a"} 1\nnet_bytes_sent{host="a",interface="eth0"} 1\n',
        'system_load1{host="a"} 1\nsystem_uptime{host="a"} 1\n',
        # Combination spread over different hosts
        'net_bytes_recv{host="a",interface="eth0"} 1\n'
        'net_bytes_sent{host="b",interface="eth0"} 1\n',
        # Missing interface label
        'net_bytes_recv{host="a"} 1\nnet_bytes_sent{host="a"} 1\n',
        # Missing host label
        'net_bytes_recv{interface="eth0"} 1\nnet_bytes_sent{interface="eth0"} 1\n',
    ],
)
def test_insufficient_families_are_not_detected(text):
    """Too few or unrelated families do not identify Telegraf."""
    assert get_metadata(text).provider_info.name == PROVIDER_NAME_GENERIC


def test_explicit_provider_identifiers_have_priority():
    """Node Exporter and cAdvisor are detected even with Telegraf families."""
    telegraf = (
        'net_bytes_recv{host="a",interface="eth0"} 1\n'
        'net_bytes_sent{host="a",interface="eth0"} 1\n'
    )
    node_exporter = 'node_exporter_build_info{version="1.8.2"} 1\n'
    cadvisor = 'cadvisor_version_info{cadvisorVersion="v0.52.1"} 1\n'
    assert (
        get_metadata(node_exporter + telegraf).provider_info.name
        == PROVIDER_NAME_NODE_EXPORTER
    )
    assert (
        get_metadata(cadvisor + telegraf).provider_info.name == PROVIDER_NAME_CADVISOR
    )


def test_minimal_configuration_offers_only_network_metrics():
    """A network-only endpoint advertises network metrics only."""
    text = (
        'net_bytes_recv{host="a",interface="eth0"} 1\n'
        'net_bytes_sent{host="a",interface="eth0"} 1\n'
    )
    metadata = get_metadata(text)
    assert metadata.available_metrics == [
        METRIC_NETWORK_RECEIVE_BYTES,
        METRIC_NETWORK_TRANSMIT_BYTES,
    ]
