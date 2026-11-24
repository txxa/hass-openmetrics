"""Regression tests for the existing providers."""

import pytest

from custom_components.openmetrics.const import (
    METRIC_CPU_USAGE_PCT,
    METRIC_DISK_USAGE_PCT,
    METRIC_MEMORY_USAGE_PCT,
    METRIC_NETWORK_RECEIVE_BYTES,
    METRIC_UPTIME_SECONDS,
    PROVIDER_NAME_CADVISOR,
    PROVIDER_NAME_GENERIC,
    PROVIDER_NAME_NODE_EXPORTER,
)
from custom_components.openmetrics.metrics.processor import OpenMetricsProcessor

from .helpers import get_metadata, poll

NODE_EXPORTER = """\
# TYPE node_exporter_build_info gauge
node_exporter_build_info{version="1.8.2"} 1
# TYPE node_uname_info gauge
node_uname_info{nodename="nas"} 1
# TYPE node_cpu_seconds_total counter
node_cpu_seconds_total{cpu="0",mode="idle"} %(idle)s
node_cpu_seconds_total{cpu="0",mode="user"} 5
# TYPE node_memory_MemTotal_bytes gauge
node_memory_MemTotal_bytes 8e+09
# TYPE node_memory_MemAvailable_bytes gauge
node_memory_MemAvailable_bytes 6e+09
# TYPE node_filesystem_size_bytes gauge
node_filesystem_size_bytes{device="/dev/sda1",mountpoint="/"} 1e+11
# TYPE node_filesystem_free_bytes gauge
node_filesystem_free_bytes{device="/dev/sda1",mountpoint="/"} 4e+10
# TYPE node_network_receive_bytes_total counter
node_network_receive_bytes_total{device="eth0"} %(rx)s
# TYPE node_network_transmit_bytes_total counter
node_network_transmit_bytes_total{device="eth0"} %(rx)s
# TYPE node_network_speed_bytes gauge
node_network_speed_bytes{device="eth0"} 1.25e+08
# TYPE node_boot_time_seconds gauge
node_boot_time_seconds 1700000000
"""

CADVISOR = """\
# TYPE cadvisor_version_info gauge
cadvisor_version_info{cadvisorVersion="v0.52.1"} 1
# TYPE machine_cpu_cores gauge
machine_cpu_cores{machine_id="abc"} 4
# TYPE container_start_time_seconds gauge
container_start_time_seconds{image="traefik:v3",name="traefik"} 1700000000
"""


def test_node_exporter_still_detected_and_processed():
    """Node Exporter keeps working (name, version, interface, metrics)."""
    processor = OpenMetricsProcessor()
    metadata = get_metadata(NODE_EXPORTER % {"idle": 100, "rx": 1000}, processor)
    assert metadata.provider_info.name == PROVIDER_NAME_NODE_EXPORTER
    assert metadata.provider_info.version == "1.8.2"
    assert "nas" in metadata.resources
    assert metadata.resources["nas"].available_metrics is None
    assert {
        METRIC_CPU_USAGE_PCT,
        METRIC_MEMORY_USAGE_PCT,
        METRIC_DISK_USAGE_PCT,
        METRIC_NETWORK_RECEIVE_BYTES,
        METRIC_UPTIME_SECONDS,
    } <= set(metadata.available_metrics)
    poll(processor, NODE_EXPORTER % {"idle": 100, "rx": 1000})
    data = poll(processor, NODE_EXPORTER % {"idle": 105, "rx": 2000})["nas"]
    assert data[METRIC_MEMORY_USAGE_PCT] == pytest.approx(25)
    assert data[f"{METRIC_DISK_USAGE_PCT}_/"] == pytest.approx(60)
    assert data[f"{METRIC_NETWORK_RECEIVE_BYTES}_eth0"] == pytest.approx(100)


def test_node_exporter_total_suffix_is_stripped():
    """Metric keys of counters still lose the '_total' suffix."""
    processor = OpenMetricsProcessor()
    families = processor.parse_data(
        NODE_EXPORTER % {"idle": 1, "rx": 1}, "text/plain; version=0.0.4"
    )
    processor.extract_metadata(families)
    metrics = processor.extract_metrics(families, [])
    assert "node_network_receive_bytes" in metrics["nas"]
    assert "node_memory_MemTotal_bytes" in metrics["nas"]


def test_cadvisor_still_detected():
    """CAdvisor keeps being detected by its version metric."""
    metadata = get_metadata(CADVISOR)
    assert metadata.provider_info.name == PROVIDER_NAME_CADVISOR


def test_unknown_endpoint_uses_generic_provider():
    """Endpoints without a known signature fall back to the generic provider."""
    text = '# TYPE foo_bar gauge\nfoo_bar{host="a"} 1\nsystem_load1{host="a"} 1\n'
    assert get_metadata(text).provider_info.name == PROVIDER_NAME_GENERIC
