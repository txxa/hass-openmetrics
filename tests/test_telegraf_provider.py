"""Tests for the Telegraf provider."""

import re
from datetime import UTC, datetime
from unittest.mock import patch

import pytest

from custom_components.openmetrics.const import (
    METRIC_CPU_USAGE_PCT,
    METRIC_DISK_USAGE_BYTES,
    METRIC_DISK_USAGE_PCT,
    METRIC_LOAD_AVERAGE_1M,
    METRIC_LOAD_AVERAGE_5M,
    METRIC_LOAD_AVERAGE_15M,
    METRIC_MEMORY_USAGE_BYTES,
    METRIC_MEMORY_USAGE_PCT,
    METRIC_NETWORK_RECEIVE_BYTES,
    METRIC_NETWORK_TRANSMIT_BYTES,
    METRIC_SWAP_USAGE_BYTES,
    METRIC_SWAP_USAGE_PCT,
    METRIC_UPTIME_SECONDS,
    PROPERTY_CPU_CORES,
    PROPERTY_DISK_SIZE,
    PROPERTY_LAST_START_TIME,
    PROPERTY_MEMORY_SIZE,
    PROPERTY_SWAP_SIZE,
    PROVIDER_NAME_TELEGRAF,
)
from custom_components.openmetrics.metrics.processor import OpenMetricsProcessor
from custom_components.openmetrics.providers.telegraf import TelegrafProvider

from .helpers import get_metadata, poll, remove_samples, set_value

CLOCK = "custom_components.openmetrics.providers.telegraf.monotonic"
HOST = "sweh00"
INTERFACES = {"ethfe", "ethsrv", "wg-home"}


# Detection and discovery
def test_detects_telegraf(sweh00):
    """Telegraf is detected from characteristic families without version metric."""
    processor = OpenMetricsProcessor()
    metadata = get_metadata(sweh00, processor)
    assert isinstance(processor._provider, TelegrafProvider)  # noqa: SLF001
    assert metadata.provider_info.name == PROVIDER_NAME_TELEGRAF


def test_detects_telegraf_without_optional_families(sweh00):
    """Detection does not depend on a single family."""
    for name in ("cpu_usage_idle", "system_uptime", "system_n_cpus", "swap_total"):
        text = remove_samples(sweh00, name)
        assert get_metadata(text).provider_info.name == PROVIDER_NAME_TELEGRAF


def test_single_family_is_not_detected():
    """A single matching family is not sufficient."""
    text = 'system_load1{host="a"} 1\nsome_other_metric{host="a"} 1\n'
    assert get_metadata(text).provider_info.name != PROVIDER_NAME_TELEGRAF


def test_families_without_host_label_are_not_detected(sweh00):
    """Families without host label do not identify Telegraf."""
    text = re.sub(r'host="sweh00"', 'instance="sweh00"', sweh00)
    assert get_metadata(text).provider_info.name != PROVIDER_NAME_TELEGRAF


def test_node_exporter_is_not_detected_as_telegraf():
    """Node Exporter and cAdvisor keep being detected by their identifier."""
    text = (
        '# TYPE node_exporter_build_info gauge\nnode_exporter_build_info{version="1.8"} 1\n'
        'node_uname_info{nodename="nas"} 1\n'
        'system_load1{host="a"} 1\nmem_total{host="a"} 1\nsystem_uptime{host="a"} 1\n'
    )
    assert get_metadata(text).provider_info.name == "Node Exporter"


def test_discovers_host_filesystems_and_interfaces(sweh00):
    """Host, filesystems with devices and all interface names are discovered."""
    metadata = get_metadata(sweh00)
    assert list(metadata.resources) == [HOST]
    resource = metadata.resources[HOST]
    assert resource.name == HOST
    assert resource.network_interfaces == INTERFACES
    assert set(resource.filesystems) == {"/", "/tmp"}  # noqa: S108
    assert resource.filesystems["/"] == "GB"
    assert resource.filesystem_devices == {"/": "vda1", "/tmp": "vdb1"}  # noqa: S108


def test_additional_labels_do_not_create_resources(sweh00):
    """Labels like location or platform do not interfere with discovery."""
    metadata = get_metadata(sweh00)
    assert set(metadata.resources) == {HOST}


def test_discovers_multiple_hosts(multi_host):
    """Multiple hosts exposed by one endpoint are discovered separately."""
    metadata = get_metadata(multi_host)
    assert set(metadata.resources) == {"alpha", "beta"}
    assert metadata.resources["alpha"].network_interfaces == {"bond0", "tun0"}
    assert metadata.resources["beta"].network_interfaces == {"enp3s0"}
    assert set(metadata.resources["alpha"].filesystems) == {"/", "/srv/data"}
    assert metadata.resources["beta"].filesystems is None


def test_available_metrics(sweh00):
    """All supported metrics are offered for a complete endpoint."""
    metadata = get_metadata(sweh00)
    expected = {
        METRIC_CPU_USAGE_PCT,
        METRIC_MEMORY_USAGE_BYTES,
        METRIC_MEMORY_USAGE_PCT,
        METRIC_SWAP_USAGE_BYTES,
        METRIC_SWAP_USAGE_PCT,
        METRIC_DISK_USAGE_BYTES,
        METRIC_DISK_USAGE_PCT,
        METRIC_NETWORK_RECEIVE_BYTES,
        METRIC_NETWORK_TRANSMIT_BYTES,
        METRIC_UPTIME_SECONDS,
        METRIC_LOAD_AVERAGE_1M,
        METRIC_LOAD_AVERAGE_5M,
        METRIC_LOAD_AVERAGE_15M,
    }
    assert set(metadata.available_metrics) == expected
    assert len(metadata.available_metrics) == len(expected)
    assert metadata.resources[HOST].available_metrics == expected


def test_only_available_metrics_are_offered(sweh00):
    """Metrics of missing families are not offered."""
    text = remove_samples(sweh00, "system_load5")
    text = remove_samples(text, "net_bytes_sent")
    text = remove_samples(text, "swap_total")
    text = remove_samples(text, "swap_used")
    text = remove_samples(text, "swap_used_percent")
    metadata = get_metadata(text)
    assert METRIC_LOAD_AVERAGE_5M not in metadata.available_metrics
    assert METRIC_NETWORK_TRANSMIT_BYTES not in metadata.available_metrics
    assert METRIC_NETWORK_RECEIVE_BYTES in metadata.available_metrics
    assert METRIC_SWAP_USAGE_PCT not in metadata.available_metrics
    assert METRIC_SWAP_USAGE_BYTES not in metadata.available_metrics


def test_available_metrics_per_host(multi_host):
    """Swap is only available for hosts having swap configured."""
    metadata = get_metadata(multi_host)
    assert METRIC_SWAP_USAGE_PCT in metadata.available_metrics
    assert METRIC_SWAP_USAGE_PCT not in metadata.resources["alpha"].available_metrics
    assert METRIC_SWAP_USAGE_PCT in metadata.resources["beta"].available_metrics
    # No disk or network metrics for host beta except the network interface
    assert METRIC_DISK_USAGE_PCT not in metadata.resources["beta"].available_metrics
    assert METRIC_LOAD_AVERAGE_5M not in metadata.available_metrics


def test_metadata_state_is_reset_between_extractions(sweh00):
    """Metrics which disappear from the endpoint are not offered anymore."""
    processor = OpenMetricsProcessor()
    assert METRIC_LOAD_AVERAGE_1M in get_metadata(sweh00, processor).available_metrics
    reduced = remove_samples(sweh00, "system_load1")
    assert (
        METRIC_LOAD_AVERAGE_1M not in get_metadata(reduced, processor).available_metrics
    )


# CPU
def test_cpu_usage_from_aggregate(sweh00):
    """CPU usage is 100 - idle of the cpu-total sample."""
    processor = OpenMetricsProcessor()
    get_metadata(sweh00, processor)
    data = poll(processor, sweh00)[HOST]
    assert data[METRIC_CPU_USAGE_PCT] == pytest.approx(100 - 68.23176823168284)
    assert data[PROPERTY_CPU_CORES] == 1


def test_cpu_usage_is_not_a_counter(sweh00):
    """Repeated polls return the percentage directly (no counter deltas)."""
    processor = OpenMetricsProcessor()
    get_metadata(sweh00, processor)
    first = poll(processor, sweh00)[HOST][METRIC_CPU_USAGE_PCT]
    second = poll(processor, set_value(sweh00, 'cpu_usage_idle{cpu="cpu-total"', "50"))[
        HOST
    ][METRIC_CPU_USAGE_PCT]
    assert first == pytest.approx(31.768231768317)
    assert second == pytest.approx(50)


def test_cpu_usage_prefers_aggregate_over_cores(multi_host):
    """The aggregate sample is used and not counted among the cores."""
    processor = OpenMetricsProcessor()
    get_metadata(multi_host, processor)
    data = poll(processor, multi_host)["alpha"]
    assert data[METRIC_CPU_USAGE_PCT] == pytest.approx(10)
    assert data[PROPERTY_CPU_CORES] == 2


def test_cpu_usage_falls_back_to_core_average(multi_host):
    """Without aggregate sample the per-core average is used."""
    processor = OpenMetricsProcessor()
    get_metadata(multi_host, processor)
    data = poll(processor, multi_host)["beta"]
    assert data[METRIC_CPU_USAGE_PCT] == pytest.approx((40 + 20 + 0) / 3)
    assert data[PROPERTY_CPU_CORES] == 3


@pytest.mark.parametrize(
    ("idle", "expected"),
    [("0", 100), ("100", 0), ("100.4", 0), ("-0.2", 100)],
)
def test_cpu_usage_is_clamped_and_zero_is_kept(sweh00, idle, expected):
    """Boundary values are valid and stay within 0..100."""
    processor = OpenMetricsProcessor()
    get_metadata(sweh00, processor)
    text = set_value(sweh00, 'cpu_usage_idle{cpu="cpu-total"', idle)
    assert poll(processor, text)[HOST][METRIC_CPU_USAGE_PCT] == expected


@pytest.mark.parametrize("invalid", ["NaN", "+Inf", "-Inf"])
def test_invalid_values_are_not_exposed_as_zero(sweh00, invalid):
    """NaN/Inf samples do not silently become zero values."""
    processor = OpenMetricsProcessor()
    get_metadata(sweh00, processor)
    text = sweh00
    for selector in (
        'cpu_usage_idle{cpu="cpu-total"',
        "mem_used_percent{",
        "mem_used{",
        "swap_used_percent{",
        "system_load1{",
        "system_uptime{",
        "disk_used_percent{",
    ):
        text = set_value(text, selector, invalid)
    data = poll(processor, text)[HOST]
    assert METRIC_CPU_USAGE_PCT not in data
    assert METRIC_LOAD_AVERAGE_1M not in data
    assert METRIC_UPTIME_SECONDS not in data
    # Disk falls back to used/total instead of zero
    assert data[f"{METRIC_DISK_USAGE_PCT}_/"] == pytest.approx(20)
    # Memory falls back to total - available and swap to used/total
    assert data[METRIC_MEMORY_USAGE_BYTES] == pytest.approx(
        3.08000768e9 - 1.537081344e9
    )
    assert data[METRIC_SWAP_USAGE_PCT] == pytest.approx(
        9.07464704e8 / 1.859121152e9 * 100
    )


# Memory and swap
def test_memory_usage(sweh00):
    """Memory values are taken directly from Telegraf."""
    processor = OpenMetricsProcessor()
    get_metadata(sweh00, processor)
    data = poll(processor, sweh00)[HOST]
    assert data[METRIC_MEMORY_USAGE_PCT] == pytest.approx(50.09488599716738)
    assert data[METRIC_MEMORY_USAGE_BYTES] == pytest.approx(1.542926336e9)
    assert data[PROPERTY_MEMORY_SIZE] == "3 GB"


def test_memory_usage_fallback_from_available(sweh00):
    """Utilization is calculated from total and available memory as fallback."""
    text = remove_samples(sweh00, "mem_used_percent")
    text = remove_samples(text, "mem_used")
    processor = OpenMetricsProcessor()
    metadata = get_metadata(text, processor)
    assert METRIC_MEMORY_USAGE_PCT in metadata.available_metrics
    assert METRIC_MEMORY_USAGE_BYTES in metadata.available_metrics
    data = poll(processor, text)[HOST]
    used = 3.08000768e9 - 1.537081344e9
    assert data[METRIC_MEMORY_USAGE_BYTES] == pytest.approx(used)
    assert data[METRIC_MEMORY_USAGE_PCT] == pytest.approx(used / 3.08000768e9 * 100)


def test_memory_is_not_mixed_with_swap(sweh00):
    """Physical memory and swap are exposed separately."""
    processor = OpenMetricsProcessor()
    get_metadata(sweh00, processor)
    data = poll(processor, sweh00)[HOST]
    assert data[METRIC_SWAP_USAGE_PCT] == pytest.approx(48.81148832198323)
    assert data[METRIC_SWAP_USAGE_BYTES] == pytest.approx(9.07464704e8)
    assert data[PROPERTY_SWAP_SIZE] == "2 GB"
    assert data[METRIC_MEMORY_USAGE_PCT] != data[METRIC_SWAP_USAGE_PCT]


def test_system_without_swap(multi_host):
    """Systems without swap do not expose swap values."""
    processor = OpenMetricsProcessor()
    get_metadata(multi_host, processor)
    data = poll(processor, multi_host)
    assert METRIC_SWAP_USAGE_PCT not in data["alpha"]
    assert METRIC_SWAP_USAGE_BYTES not in data["alpha"]
    assert data["beta"][METRIC_SWAP_USAGE_PCT] == 25
    assert data["beta"][METRIC_SWAP_USAGE_BYTES] == 5e8


def test_zero_swap_usage_is_exposed(sweh00):
    """A swap usage of zero is a valid value."""
    processor = OpenMetricsProcessor()
    get_metadata(sweh00, processor)
    text = set_value(sweh00, "swap_used", "0")
    text = set_value(text, "swap_used_percent", "0")
    data = poll(processor, text)[HOST]
    assert data[METRIC_SWAP_USAGE_PCT] == 0
    assert data[METRIC_SWAP_USAGE_BYTES] == 0


# Filesystems
def test_multiple_filesystems(sweh00):
    """Each mount point gets its own values."""
    processor = OpenMetricsProcessor()
    get_metadata(sweh00, processor)
    data = poll(processor, sweh00)[HOST]
    assert data[f"{METRIC_DISK_USAGE_PCT}_/"] == pytest.approx(43.7600797910119)
    assert data[f"{METRIC_DISK_USAGE_PCT}_/tmp"] == pytest.approx(2.491303165448478)
    assert data[f"{METRIC_DISK_USAGE_BYTES}_/"] == pytest.approx(4.0e9)
    assert data[f"{METRIC_DISK_USAGE_BYTES}_/tmp"] == pytest.approx(2.0e8)
    assert data[PROPERTY_DISK_SIZE] == {"/": "20 GB", "/tmp": "10 GB"}  # noqa: S108


def test_filesystem_fallback_from_bytes(multi_host):
    """Utilization is calculated from byte values if no percentage exists."""
    processor = OpenMetricsProcessor()
    get_metadata(multi_host, processor)
    data = poll(processor, multi_host)["alpha"]
    assert data[f"{METRIC_DISK_USAGE_PCT}_/"] == pytest.approx(60)
    assert data[f"{METRIC_DISK_USAGE_BYTES}_/"] == pytest.approx(6e10)
    assert data[f"{METRIC_DISK_USAGE_PCT}_/srv/data"] == 0
    assert data[f"{METRIC_DISK_USAGE_BYTES}_/srv/data"] == 0


# Network
def test_network_rate_requires_previous_sample(sweh00, clock):
    """The first measurement does not produce a rate."""
    processor = OpenMetricsProcessor()
    get_metadata(sweh00, processor)
    data = poll(processor, sweh00)[HOST]
    assert not [key for key in data if key.startswith("network_")]


def test_network_rate(sweh00, clock):
    """Rates are the counter difference divided by the elapsed time."""
    processor = OpenMetricsProcessor()
    get_metadata(sweh00, processor)
    poll(processor, sweh00)
    clock.now += 4
    text = set_value(
        sweh00, 'net_bytes_recv{host="sweh00",interface="wg-home"', "1.74172448e+08"
    )
    text = set_value(
        text, 'net_bytes_recv{host="sweh00",interface="ethfe"', "1.0945178263e+10"
    )
    text = set_value(
        text, 'net_bytes_sent{host="sweh00",interface="ethfe"', "8.39591858e+08"
    )
    data = poll(processor, text)[HOST]
    assert data[f"{METRIC_NETWORK_RECEIVE_BYTES}_ethfe"] == pytest.approx(100)
    assert data[f"{METRIC_NETWORK_TRANSMIT_BYTES}_ethfe"] == pytest.approx(100)
    assert data[f"{METRIC_NETWORK_RECEIVE_BYTES}_wg-home"] == 0
    assert data[f"{METRIC_NETWORK_RECEIVE_BYTES}_ethsrv"] == 0


def test_network_rate_uses_actual_elapsed_time(sweh00, clock):
    """Irregular polling intervals and the update interval argument are respected."""
    processor = OpenMetricsProcessor()
    get_metadata(sweh00, processor)
    poll(processor, sweh00, interval=10)
    selector = 'net_bytes_recv{host="sweh00",interface="ethfe"'
    clock.now += 2.5
    rate = poll(processor, set_value(sweh00, selector, "1.0945178363e+10"), interval=10)
    assert rate[HOST][f"{METRIC_NETWORK_RECEIVE_BYTES}_ethfe"] == pytest.approx(
        500 / 2.5
    )
    clock.now += 47
    rate = poll(processor, set_value(sweh00, selector, "1.0945178863e+10"), interval=10)
    assert rate[HOST][f"{METRIC_NETWORK_RECEIVE_BYTES}_ethfe"] == pytest.approx(
        500 / 47
    )


def test_network_counter_reset_is_never_negative(sweh00, clock):
    """A counter reset yields no value and the next cycle recovers."""
    processor = OpenMetricsProcessor()
    get_metadata(sweh00, processor)
    poll(processor, sweh00)
    selector = 'net_bytes_recv{host="sweh00",interface="ethfe"'
    clock.now += 10
    data = poll(processor, set_value(sweh00, selector, "1000"))[HOST]
    assert f"{METRIC_NETWORK_RECEIVE_BYTES}_ethfe" not in data
    assert data[f"{METRIC_NETWORK_RECEIVE_BYTES}_ethsrv"] == 0
    clock.now += 10
    data = poll(processor, set_value(sweh00, selector, "3000"))[HOST]
    assert data[f"{METRIC_NETWORK_RECEIVE_BYTES}_ethfe"] == pytest.approx(200)


def test_network_host_reboot(sweh00, clock):
    """All counters resetting at once (reboot) never yields negative rates."""
    processor = OpenMetricsProcessor()
    get_metadata(sweh00, processor)
    poll(processor, sweh00)
    clock.now += 10
    text = re.sub(
        r"^(net_bytes_(?:recv|sent)\{[^}]*\} )\S+$",
        r"\g<1>10",
        sweh00,
        flags=re.MULTILINE,
    )
    text = set_value(text, "system_uptime", "5")
    data = poll(processor, text)[HOST]
    assert not [key for key in data if key.startswith("network_")]
    assert data[METRIC_UPTIME_SECONDS] == 5


def test_network_interface_disappears_and_reappears(sweh00, clock):
    """A reappearing interface starts with a new baseline."""
    processor = OpenMetricsProcessor()
    get_metadata(sweh00, processor)
    poll(processor, sweh00)
    without = "\n".join(line for line in sweh00.splitlines() if "wg-home" not in line)
    clock.now += 10
    data = poll(processor, without)[HOST]
    assert f"{METRIC_NETWORK_RECEIVE_BYTES}_wg-home" not in data
    assert f"{METRIC_NETWORK_RECEIVE_BYTES}_ethfe" in data
    clock.now += 10
    data = poll(processor, sweh00)[HOST]
    assert f"{METRIC_NETWORK_RECEIVE_BYTES}_wg-home" not in data
    clock.now += 10
    data = poll(processor, sweh00)[HOST]
    assert data[f"{METRIC_NETWORK_RECEIVE_BYTES}_wg-home"] == 0


def test_network_missing_metric_and_zero_elapsed_time(sweh00, clock):
    """Missing families and a zero elapsed time do not produce values."""
    processor = OpenMetricsProcessor()
    get_metadata(sweh00, processor)
    poll(processor, sweh00)
    selector = 'net_bytes_recv{host="sweh00",interface="ethfe"'
    # Zero elapsed time: no rate, baseline is kept
    data = poll(processor, set_value(sweh00, selector, "1.0945178863e+10"))[HOST]
    assert f"{METRIC_NETWORK_RECEIVE_BYTES}_ethfe" not in data
    # Missing receive family: only transmit rates are available
    clock.now += 10
    data = poll(processor, remove_samples(sweh00, "net_bytes_recv"))[HOST]
    assert not [k for k in data if k.startswith(METRIC_NETWORK_RECEIVE_BYTES)]
    assert f"{METRIC_NETWORK_TRANSMIT_BYTES}_ethfe" in data
    # Baseline of the missing family was dropped
    clock.now += 10
    data = poll(processor, sweh00)[HOST]
    assert not [k for k in data if k.startswith(METRIC_NETWORK_RECEIVE_BYTES)]


def test_network_rate_spans_failed_polls(sweh00, clock):
    """The elapsed time between successful measurements is used."""
    processor = OpenMetricsProcessor()
    get_metadata(sweh00, processor)
    poll(processor, sweh00)
    clock.now += 120  # several failed polling cycles in between
    text = set_value(
        sweh00, 'net_bytes_recv{host="sweh00",interface="ethfe"', "1.0945179063e+10"
    )
    data = poll(processor, text)[HOST]
    assert data[f"{METRIC_NETWORK_RECEIVE_BYTES}_ethfe"] == pytest.approx(1200 / 120)


@pytest.mark.parametrize(
    "interface",
    ["eth0", "ethfe", "ethsrv", "enp3s0", "wg-home", "tun0", "ppp0", "bond0", "br0"],
)
def test_arbitrary_interface_names(interface, clock):
    """Any valid Linux interface name is supported."""
    template = (
        '# TYPE net_bytes_recv counter\nnet_bytes_recv{{host="h",interface="{i}"}} {v}\n'
        '# TYPE net_bytes_sent counter\nnet_bytes_sent{{host="h",interface="{i}"}} {v}\n'
        '# TYPE system_load1 gauge\nsystem_load1{{host="h"}} 1\n'
        '# TYPE system_uptime gauge\nsystem_uptime{{host="h"}} 1\n'
    )
    processor = OpenMetricsProcessor()
    metadata = get_metadata(template.format(i=interface, v=1000), processor)
    assert metadata.resources["h"].network_interfaces == {interface}
    poll(processor, template.format(i=interface, v=1000))
    clock.now += 10
    data = poll(processor, template.format(i=interface, v=2000))["h"]
    assert data[f"{METRIC_NETWORK_RECEIVE_BYTES}_{interface}"] == pytest.approx(100)
    assert data[f"{METRIC_NETWORK_TRANSMIT_BYTES}_{interface}"] == pytest.approx(100)


def test_network_counters_are_tracked_per_host(multi_host, clock):
    """Hosts do not share network baselines."""
    processor = OpenMetricsProcessor()
    get_metadata(multi_host, processor)
    poll(processor, multi_host)
    clock.now += 10
    text = set_value(multi_host, 'net_bytes_recv{host="beta"', "5100")
    data = poll(processor, text)
    assert data["beta"][f"{METRIC_NETWORK_RECEIVE_BYTES}_enp3s0"] == pytest.approx(10)
    assert data["alpha"][f"{METRIC_NETWORK_RECEIVE_BYTES}_bond0"] == 0


def test_network_state_is_dropped_for_missing_host(multi_host, clock):
    """A host which disappears starts with a new baseline when it returns."""
    processor = OpenMetricsProcessor()
    get_metadata(multi_host, processor)
    poll(processor, multi_host)
    only_alpha = "\n".join(
        line for line in multi_host.splitlines() if 'host="beta"' not in line
    )
    clock.now += 10
    poll(processor, only_alpha)
    clock.now += 10
    data = poll(processor, multi_host)
    assert not [k for k in data["beta"] if k.startswith("network_")]


# Uptime and load
def test_uptime(sweh00):
    """Uptime is used directly and the start time derived from it."""
    processor = OpenMetricsProcessor()
    get_metadata(sweh00, processor)
    now = datetime(2025, 1, 10, 12, 0, 0, tzinfo=UTC)
    with patch(
        "custom_components.openmetrics.providers.telegraf.dt_util.utcnow",
        return_value=now,
    ):
        data = poll(processor, sweh00)[HOST]
    assert data[METRIC_UPTIME_SECONDS] == 341695
    assert data[PROPERTY_LAST_START_TIME] == datetime(2025, 1, 6, 13, 5, 5, tzinfo=UTC)


def test_load_averages(sweh00):
    """Load averages are exposed as separate raw values."""
    processor = OpenMetricsProcessor()
    get_metadata(sweh00, processor)
    data = poll(processor, sweh00)[HOST]
    assert data[METRIC_LOAD_AVERAGE_1M] == 0.29
    assert data[METRIC_LOAD_AVERAGE_5M] == 0.38
    assert data[METRIC_LOAD_AVERAGE_15M] == 0.33


def test_zero_load_is_exposed(multi_host):
    """A load of zero is a valid value."""
    processor = OpenMetricsProcessor()
    get_metadata(multi_host, processor)
    data = poll(processor, multi_host)
    assert data["alpha"][METRIC_LOAD_AVERAGE_1M] == 0
    assert data["beta"][METRIC_LOAD_AVERAGE_1M] == 1.5


# Parsing
@pytest.mark.parametrize("metric_type", ["gauge", "counter", "untyped"])
def test_metric_types(metric_type, clock):
    """Counters (also with the _total suffix munged by the parser) work."""

    def text(value):
        return (
            f"# TYPE net_bytes_recv {metric_type}\n"
            f'net_bytes_recv{{host="h",interface="eth0"}} {value}\n'
            f"# TYPE mem_total {metric_type if metric_type != 'counter' else 'gauge'}\n"
            f'mem_total{{host="h"}} 1e9\n'
            f"# TYPE mem_used {metric_type if metric_type != 'counter' else 'gauge'}\n"
            f'mem_used{{host="h"}} 5e8\n'
        )

    processor = OpenMetricsProcessor()
    get_metadata(text(1000), processor)
    poll(processor, text(1000))
    clock.now += 10
    data = poll(processor, text("2.0e+03"))["h"]
    assert data[f"{METRIC_NETWORK_RECEIVE_BYTES}_eth0"] == pytest.approx(100)
    assert data[METRIC_MEMORY_USAGE_BYTES] == 5e8


def test_hosts_without_host_label_are_ignored(sweh00):
    """Samples without host label are ignored."""
    text = sweh00 + '\nsystem_load1 5\nmem_total{instance="x"} 1\n'
    processor = OpenMetricsProcessor()
    metadata = get_metadata(text, processor)
    assert set(metadata.resources) == {HOST}
    assert poll(processor, text)[HOST][METRIC_LOAD_AVERAGE_1M] == 0.29


# Reboot detection by uptime
def _bump_counters(text: str, delta: float, uptime: str | None) -> str:
    """Add delta to all network counters and optionally set the uptime."""
    text = re.sub(
        r"^(net_bytes_(?:recv|sent)\{[^}]*\} )(\S+)$",
        lambda m: f"{m.group(1)}{float(m.group(2)) + delta}",
        text,
        flags=re.MULTILINE,
    )
    if uptime is None:
        return remove_samples(text, "system_uptime")
    return set_value(text, "system_uptime", uptime)


def _rates(data: dict) -> dict:
    return {key: value for key, value in data.items() if key.startswith("network_")}


def test_reboot_with_increasing_counters_is_detected_by_uptime(sweh00, clock):
    """Counters above the old ones do not yield a rate after a reboot."""
    processor = OpenMetricsProcessor()
    get_metadata(sweh00, processor)
    poll(processor, sweh00)
    clock.now += 10
    # The host rebooted and already transferred more than before
    text = _bump_counters(sweh00, 1e12, "30")
    assert not _rates(poll(processor, text)[HOST])
    # Recovery: the counters after the reboot are the new baseline
    clock.now += 10
    data = poll(processor, _bump_counters(text, 1000, "40"))[HOST]
    assert data[f"{METRIC_NETWORK_RECEIVE_BYTES}_ethfe"] == pytest.approx(100)
    assert data[f"{METRIC_NETWORK_TRANSMIT_BYTES}_wg-home"] == pytest.approx(100)


def test_reboot_with_decreasing_counters_and_recovery(sweh00, clock):
    """Reboot with smaller counters yields no rate and recovers afterwards."""
    processor = OpenMetricsProcessor()
    get_metadata(sweh00, processor)
    poll(processor, sweh00)
    clock.now += 10
    text = _bump_counters(sweh00, -sweh00_counter_floor(sweh00), "20")
    assert not _rates(poll(processor, text)[HOST])
    clock.now += 10
    data = poll(processor, _bump_counters(text, 500, "30"))[HOST]
    assert data[f"{METRIC_NETWORK_RECEIVE_BYTES}_ethsrv"] == pytest.approx(50)


def sweh00_counter_floor(text: str) -> float:
    """Return a delta which makes all counters of the fixture small."""
    values = re.findall(r"^net_bytes_(?:recv|sent)\{[^}]*\} (\S+)$", text, re.MULTILINE)
    return min(float(value) for value in values) - 5


def test_unchanged_uptime_does_not_invalidate_baselines(sweh00, clock):
    """Cached Telegraf samples (same uptime) still produce rates."""
    processor = OpenMetricsProcessor()
    get_metadata(sweh00, processor)
    poll(processor, sweh00)
    clock.now += 10
    uptime = "341695"
    data = poll(processor, _bump_counters(sweh00, 1000, uptime))[HOST]
    assert data[f"{METRIC_NETWORK_RECEIVE_BYTES}_ethfe"] == pytest.approx(100)
    # Fully cached sample: valid zero throughput
    clock.now += 10
    data = poll(processor, _bump_counters(sweh00, 1000, uptime))[HOST]
    assert data[f"{METRIC_NETWORK_RECEIVE_BYTES}_ethfe"] == 0
    assert data[f"{METRIC_NETWORK_TRANSMIT_BYTES}_ethfe"] == 0


def test_increasing_uptime_keeps_baselines(sweh00, clock):
    """A regularly increasing uptime does not invalidate baselines."""
    processor = OpenMetricsProcessor()
    get_metadata(sweh00, processor)
    poll(processor, sweh00)
    clock.now += 10
    data = poll(processor, _bump_counters(sweh00, 1000, "341705"))[HOST]
    assert data[f"{METRIC_NETWORK_RECEIVE_BYTES}_ethfe"] == pytest.approx(100)


def test_missing_uptime_preserves_counter_based_behaviour(sweh00, clock):
    """Without uptime only decreasing counters indicate resets."""
    processor = OpenMetricsProcessor()
    get_metadata(sweh00, processor)
    poll(processor, _bump_counters(sweh00, 0, None))
    clock.now += 10
    data = poll(processor, _bump_counters(sweh00, 1000, None))[HOST]
    assert data[f"{METRIC_NETWORK_RECEIVE_BYTES}_ethfe"] == pytest.approx(100)
    clock.now += 10
    data = poll(processor, _bump_counters(sweh00, -1000, None))[HOST]
    assert not _rates(data)


def test_uptime_missing_in_single_poll_keeps_previous_uptime(sweh00, clock):
    """A reboot is still detected after a poll without uptime."""
    processor = OpenMetricsProcessor()
    get_metadata(sweh00, processor)
    poll(processor, sweh00)
    clock.now += 10
    data = poll(processor, _bump_counters(sweh00, 1000, None))[HOST]
    assert data[f"{METRIC_NETWORK_RECEIVE_BYTES}_ethfe"] == pytest.approx(100)
    clock.now += 10
    assert not _rates(poll(processor, _bump_counters(sweh00, 5000, "10"))[HOST])


def test_reboot_of_one_host_does_not_affect_other_hosts(multi_host, clock):
    """Only the baselines of the rebooted host are invalidated."""
    processor = OpenMetricsProcessor()
    get_metadata(multi_host, processor)
    poll(processor, multi_host)
    clock.now += 10
    text = _bump_counters(multi_host, 1000, "300")
    text = set_value(text, 'system_uptime{host="alpha"', "5")
    data = poll(processor, text)
    assert not _rates(data["alpha"])
    assert data["beta"][f"{METRIC_NETWORK_RECEIVE_BYTES}_enp3s0"] == pytest.approx(100)


def test_zero_throughput_is_a_valid_measurement(sweh00, clock):
    """Unchanged counters give 0 and not a missing value."""
    processor = OpenMetricsProcessor()
    get_metadata(sweh00, processor)
    poll(processor, sweh00)
    clock.now += 10
    data = poll(processor, sweh00)[HOST]
    assert data[f"{METRIC_NETWORK_RECEIVE_BYTES}_wg-home"] == 0


# Numeric validation
@pytest.mark.parametrize("value", ["150", "-5", "NaN", "+Inf"])
def test_out_of_range_percentages_are_not_clamped(sweh00, value):
    """Direct percentages outside 0..100 fall back to the byte values."""
    processor = OpenMetricsProcessor()
    get_metadata(sweh00, processor)
    text = set_value(sweh00, "mem_used_percent{", value)
    text = set_value(text, "swap_used_percent{", value)
    text = set_value(text, "disk_used_percent{", value)
    text = set_value(text, 'cpu_usage_idle{cpu="cpu-total"', value)
    data = poll(processor, text)[HOST]
    assert METRIC_CPU_USAGE_PCT not in data
    assert data[METRIC_MEMORY_USAGE_PCT] == pytest.approx(
        1.542926336 / 3.08000768 * 100
    )
    assert data[METRIC_SWAP_USAGE_PCT] == pytest.approx(9.07464704 / 18.59121152 * 100)
    assert data[f"{METRIC_DISK_USAGE_PCT}_/"] == pytest.approx(20)


def test_derived_percentage_out_of_range_is_not_exposed(sweh00):
    """Used bytes far above the total do not become a clamped 100 %."""
    processor = OpenMetricsProcessor()
    get_metadata(sweh00, processor)
    text = remove_samples(sweh00, "mem_used_percent")
    text = set_value(text, "mem_used{", "9e+09")
    data = poll(processor, text)[HOST]
    assert METRIC_MEMORY_USAGE_PCT not in data
    assert data[METRIC_MEMORY_USAGE_BYTES] == pytest.approx(9e9)


def test_zero_total_and_inconsistent_available_are_not_exposed(sweh00):
    """Zero denominators and available above total give no derived values."""
    processor = OpenMetricsProcessor()
    get_metadata(sweh00, processor)
    text = remove_samples(remove_samples(sweh00, "mem_used_percent"), "mem_used")
    zero = set_value(text, "mem_total{", "0")
    data = poll(processor, zero)[HOST]
    assert METRIC_MEMORY_USAGE_PCT not in data
    assert METRIC_MEMORY_USAGE_BYTES not in data
    data = poll(processor, set_value(text, "mem_available{", "9e+09"))[HOST]
    assert METRIC_MEMORY_USAGE_PCT not in data
    assert METRIC_MEMORY_USAGE_BYTES not in data


@pytest.mark.parametrize("uptime", ["1e+30", "1e+300", "-1", "NaN", "+Inf"])
def test_invalid_uptime_does_not_break_the_polling_cycle(sweh00, uptime):
    """Invalid or excessively large uptimes only omit the uptime metrics."""
    processor = OpenMetricsProcessor()
    get_metadata(sweh00, processor)
    data = poll(processor, set_value(sweh00, "system_uptime", uptime))[HOST]
    assert METRIC_UPTIME_SECONDS not in data
    assert PROPERTY_LAST_START_TIME not in data
    assert data[METRIC_LOAD_AVERAGE_1M] == 0.29
    assert METRIC_MEMORY_USAGE_PCT in data


def test_invalid_uptime_does_not_trigger_reboot_detection(sweh00, clock):
    """An invalid uptime neither is a reboot nor replaces the last valid uptime."""
    processor = OpenMetricsProcessor()
    get_metadata(sweh00, processor)
    poll(processor, sweh00)
    clock.now += 10
    text = _bump_counters(sweh00, 1000, "NaN")
    data = poll(processor, text)[HOST]
    assert data[f"{METRIC_NETWORK_RECEIVE_BYTES}_ethfe"] == pytest.approx(100)


def test_negative_values_are_not_exposed(sweh00):
    """Negative gauges are invalid."""
    processor = OpenMetricsProcessor()
    get_metadata(sweh00, processor)
    text = set_value(sweh00, "system_load1{", "-1")
    text = set_value(text, "mem_used{", "-1")
    data = poll(processor, text)[HOST]
    assert METRIC_LOAD_AVERAGE_1M not in data
    assert data[METRIC_MEMORY_USAGE_BYTES] == pytest.approx(
        3.08000768e9 - 1.537081344e9
    )


def test_cpu_idle_rounding_errors_are_clamped(sweh00):
    """Tiny overshoots caused by rounding are clamped to the valid range."""
    processor = OpenMetricsProcessor()
    get_metadata(sweh00, processor)
    text = set_value(sweh00, 'cpu_usage_idle{cpu="cpu-total"', "100.0000001")
    assert poll(processor, text)[HOST][METRIC_CPU_USAGE_PCT] == 0


def test_huge_sizes_do_not_break_the_polling_cycle(sweh00):
    """Very large byte values are handled."""
    processor = OpenMetricsProcessor()
    get_metadata(sweh00, processor)
    text = set_value(sweh00, "mem_total{", "1e+300")
    text = set_value(text, "disk_total{", "1e+300")
    data = poll(processor, text)[HOST]
    assert METRIC_MEMORY_USAGE_BYTES in data
