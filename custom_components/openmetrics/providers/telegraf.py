"""Telegraf metrics provider (outputs.prometheus_client)."""

import math
from dataclasses import dataclass, field
from datetime import timedelta
from time import monotonic
from typing import Any

from homeassistant.const import UnitOfInformation
from homeassistant.util import dt as dt_util

from ..const import (
    METRIC_CPU_USAGE_PCT,
    METRIC_DISK_USAGE_BYTES,
    METRIC_DISK_USAGE_PCT,
    METRIC_FAIL2BAN_BANNED,
    METRIC_FAIL2BAN_BANNED_TOTAL,
    METRIC_FAIL2BAN_FAILED,
    METRIC_FAIL2BAN_FAILED_TOTAL,
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
    RESOURCE_TYPE_NODE,
)
from ..lib.metrics_core import Metric
from ..lib.samples import Sample
from ..metrics import MetricFilter
from ..metrics.data import ProviderInfoData, ResourceInfoData
from ..unit_converters import convert_data_size, get_appropriate_unit
from .base import MetricsProvider

# Metrics
TELEGRAF_CPU_USAGE_IDLE = "cpu_usage_idle"
TELEGRAF_CPU_USAGE_USER = "cpu_usage_user"
TELEGRAF_CPU_USAGE_SYSTEM = "cpu_usage_system"
TELEGRAF_SYSTEM_N_CPUS = "system_n_cpus"
TELEGRAF_MEM_USED_PERCENT = "mem_used_percent"
TELEGRAF_MEM_USED = "mem_used"
TELEGRAF_MEM_TOTAL = "mem_total"
TELEGRAF_MEM_AVAILABLE = "mem_available"
TELEGRAF_SWAP_USED_PERCENT = "swap_used_percent"
TELEGRAF_SWAP_USED = "swap_used"
TELEGRAF_SWAP_TOTAL = "swap_total"
TELEGRAF_DISK_USED_PERCENT = "disk_used_percent"
TELEGRAF_DISK_USED = "disk_used"
TELEGRAF_DISK_FREE = "disk_free"
TELEGRAF_DISK_TOTAL = "disk_total"
TELEGRAF_SYSTEM_LOAD1 = "system_load1"
TELEGRAF_SYSTEM_LOAD5 = "system_load5"
TELEGRAF_SYSTEM_LOAD15 = "system_load15"
TELEGRAF_NET_BYTES_RECV = "net_bytes_recv"
TELEGRAF_NET_BYTES_SENT = "net_bytes_sent"
TELEGRAF_SYSTEM_UPTIME = "system_uptime"
TELEGRAF_FAIL2BAN_BANNED = "fail2ban_banned"
TELEGRAF_FAIL2BAN_FAILED = "fail2ban_failed"
# Labels
TELEGRAF_HOST_LABEL = "host"
TELEGRAF_CPU_LABEL = "cpu"
TELEGRAF_DISK_PATH_LABEL = "path"
TELEGRAF_DISK_DEVICE_LABEL = "device"
TELEGRAF_NETWORK_INTERFACE_LABEL = "interface"
TELEGRAF_FAIL2BAN_JAIL_LABEL = "jail"
# Values
TELEGRAF_CPU_TOTAL = "cpu-total"
# Regex
TELEGRAF_AT_LEAST_ONE_CHARACTER_REGEX = ".+"

# Required labels of each supported metric family
_HOST_ONLY = (TELEGRAF_HOST_LABEL,)
_CPU_LABELS = (TELEGRAF_HOST_LABEL, TELEGRAF_CPU_LABEL)
_DISK_LABELS = (TELEGRAF_HOST_LABEL, TELEGRAF_DISK_PATH_LABEL)
_NETWORK_LABELS = (TELEGRAF_HOST_LABEL, TELEGRAF_NETWORK_INTERFACE_LABEL)
_FAIL2BAN_LABELS = (TELEGRAF_HOST_LABEL, TELEGRAF_FAIL2BAN_JAIL_LABEL)
FAMILY_LABELS: dict[str, tuple[str, ...]] = {
    TELEGRAF_CPU_USAGE_IDLE: _CPU_LABELS,
    TELEGRAF_CPU_USAGE_USER: _CPU_LABELS,
    TELEGRAF_CPU_USAGE_SYSTEM: _CPU_LABELS,
    TELEGRAF_SYSTEM_N_CPUS: _HOST_ONLY,
    TELEGRAF_MEM_USED_PERCENT: _HOST_ONLY,
    TELEGRAF_MEM_USED: _HOST_ONLY,
    TELEGRAF_MEM_TOTAL: _HOST_ONLY,
    TELEGRAF_MEM_AVAILABLE: _HOST_ONLY,
    TELEGRAF_SWAP_USED_PERCENT: _HOST_ONLY,
    TELEGRAF_SWAP_USED: _HOST_ONLY,
    TELEGRAF_SWAP_TOTAL: _HOST_ONLY,
    TELEGRAF_DISK_USED_PERCENT: _DISK_LABELS,
    TELEGRAF_DISK_USED: _DISK_LABELS,
    TELEGRAF_DISK_FREE: _DISK_LABELS,
    TELEGRAF_DISK_TOTAL: _DISK_LABELS,
    TELEGRAF_SYSTEM_LOAD1: _HOST_ONLY,
    TELEGRAF_SYSTEM_LOAD5: _HOST_ONLY,
    TELEGRAF_SYSTEM_LOAD15: _HOST_ONLY,
    TELEGRAF_NET_BYTES_RECV: _NETWORK_LABELS,
    TELEGRAF_NET_BYTES_SENT: _NETWORK_LABELS,
    TELEGRAF_SYSTEM_UPTIME: _HOST_ONLY,
    TELEGRAF_FAIL2BAN_BANNED: _FAIL2BAN_LABELS,
    TELEGRAF_FAIL2BAN_FAILED: _FAIL2BAN_LABELS,
}
# Families which are only used to detect Telegraf
DETECTION_ONLY_FAMILIES = (TELEGRAF_CPU_USAGE_USER, TELEGRAF_CPU_USAGE_SYSTEM)
# Number of distinct characteristic families required to detect Telegraf
DETECTION_MIN_FAMILIES = 3
# Distinctive combinations of families (on the same host) which also identify
# Telegraf, so that endpoints with only a few input plugins are detected
DETECTION_COMBINATIONS: tuple[frozenset[str], ...] = (
    frozenset({TELEGRAF_NET_BYTES_RECV, TELEGRAF_NET_BYTES_SENT}),
    frozenset({TELEGRAF_MEM_USED_PERCENT, TELEGRAF_MEM_TOTAL}),
    frozenset({TELEGRAF_SWAP_USED_PERCENT, TELEGRAF_SWAP_TOTAL}),
    frozenset({TELEGRAF_DISK_USED_PERCENT, TELEGRAF_DISK_TOTAL}),
    frozenset({TELEGRAF_FAIL2BAN_BANNED, TELEGRAF_FAIL2BAN_FAILED}),
)
# Order in which the supported metrics are offered
SUPPORTED_METRIC_ORDER = (
    METRIC_CPU_USAGE_PCT,
    METRIC_MEMORY_USAGE_PCT,
    METRIC_MEMORY_USAGE_BYTES,
    METRIC_SWAP_USAGE_PCT,
    METRIC_SWAP_USAGE_BYTES,
    METRIC_DISK_USAGE_PCT,
    METRIC_DISK_USAGE_BYTES,
    METRIC_NETWORK_RECEIVE_BYTES,
    METRIC_NETWORK_TRANSMIT_BYTES,
    METRIC_UPTIME_SECONDS,
    METRIC_LOAD_AVERAGE_1M,
    METRIC_LOAD_AVERAGE_5M,
    METRIC_LOAD_AVERAGE_15M,
    METRIC_FAIL2BAN_BANNED,
    METRIC_FAIL2BAN_FAILED,
    METRIC_FAIL2BAN_BANNED_TOTAL,
    METRIC_FAIL2BAN_FAILED_TOTAL,
)
# Per-jail metric and its host total
FAIL2BAN_TOTALS = {
    METRIC_FAIL2BAN_BANNED: METRIC_FAIL2BAN_BANNED_TOTAL,
    METRIC_FAIL2BAN_FAILED: METRIC_FAIL2BAN_FAILED_TOTAL,
}
# Marker for hosts without configured swap
_SWAP_UNCONFIGURED = "swap_unconfigured"
# Percentages slightly outside of 0..100 (rounding) are clamped, others are invalid
PERCENT_TOLERANCE = 1.0
# Shorter intervals between two measurements are not suitable to calculate rates
MIN_ELAPSED_SECONDS = 0.1


def _metric_filter(name: str) -> MetricFilter:
    """Create a metric filter selecting all samples of a supported family."""
    label_filters = dict.fromkeys(
        FAMILY_LABELS[name], TELEGRAF_AT_LEAST_ONE_CHARACTER_REGEX
    )
    return MetricFilter(
        metric_key=f"^{name}$",
        resource_label=TELEGRAF_HOST_LABEL,
        label_filters=label_filters,
    )


def _number(value: Any) -> float | None:
    """Return value as finite float or None if it is not a valid number."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value) if math.isfinite(value) else None


def _non_negative(value: Any) -> float | None:
    """Return value as finite non-negative float or None."""
    number = _number(value)
    return number if number is not None and number >= 0 else None


def _count(value: Any) -> int | None:
    """Return value as finite non-negative integer or None."""
    number = _non_negative(value)
    return int(number) if number is not None and number.is_integer() else None


def _valid_uptime(value: Any) -> float | None:
    """Return the uptime in seconds if it is valid (boot after the Unix epoch)."""
    uptime = _non_negative(value)
    if uptime is None or uptime > dt_util.utcnow().timestamp():
        return None
    return uptime


def _percentage(value: Any) -> float | None:
    """Return a valid percentage (rounding errors clamped) or None."""
    number = _number(value)
    if number is None or not -PERCENT_TOLERANCE <= number <= 100 + PERCENT_TOLERANCE:
        return None
    return min(max(number, 0), 100)


def _format_size(size_bytes: float) -> str:
    """Format a byte value with its most appropriate unit."""
    target_unit = get_appropriate_unit(size_bytes)
    return f"{round(convert_data_size(size_bytes, target_unit))} {target_unit}"


def _calculate_usage(
    total: float | None,
    used: float | None,
    available: float | None,
    used_pct: float | None,
) -> tuple[float | None, float | None]:
    """Calculate used bytes and used percentage from the available values.

    Values which cannot be derived consistently (zero total, available above
    total, percentages out of range) are None instead of misleading numbers.
    """
    if used is None and total and available is not None and available <= total:
        used = total - available
    if used_pct is None and total and used is not None:
        used_pct = _percentage(used / total * 100)
    return used, used_pct


@dataclass
class _HostFamilies:
    """Telegraf families seen for a host and its interfaces and filesystems."""

    host: set[str] = field(default_factory=set)
    interfaces: dict[str, set[str]] = field(default_factory=dict)
    filesystems: dict[str, set[str]] = field(default_factory=dict)
    jails: dict[str, set[str]] = field(default_factory=dict)


class TelegrafProvider(MetricsProvider):
    """Metrics provider for Telegraf's Prometheus output."""

    metric_filters = [
        _metric_filter(name)
        for name in FAMILY_LABELS
        if name not in DETECTION_ONLY_FAMILIES
    ]

    def __init__(self):
        """Initialize Telegraf provider."""
        super().__init__(PROVIDER_NAME_TELEGRAF, RESOURCE_TYPE_NODE)
        self.provider_filters: list[MetricFilter] = []
        # Telegraf families seen per host during metadata extraction
        self._host_families: dict[str, _HostFamilies] = {}

    # Detection and metadata
    def matches_families(self, families: list[Metric]) -> bool:
        """Detect Telegraf by characteristic families and labels.

        Either several distinct families or one distinctive combination of
        families on the same host has to be exposed.
        """
        hosts: dict[str, set[str]] = {}
        for family in families:
            required = FAMILY_LABELS.get(family.name)
            if required is None:
                continue
            found = {
                sample.labels[TELEGRAF_HOST_LABEL]
                for sample in family.samples
                if all(sample.labels.get(label) for label in required)
            }
            if found:
                hosts[family.name] = found
        if len(hosts) >= DETECTION_MIN_FAMILIES:
            return True
        return any(
            set.intersection(*(hosts.get(name, set()) for name in combination))
            for combination in DETECTION_COMBINATIONS
        )

    def extract_provider_info(self, family: Metric, provider_info: ProviderInfoData):
        """Extract provider information (Telegraf does not expose any)."""

    def extract_resource_info(self, family: Metric, resources: dict):
        """Extract hosts, filesystems and network interfaces."""
        required = FAMILY_LABELS.get(family.name)
        if required is None:
            return
        for sample in family.samples:
            # Samples without all required labels do not create resources
            if not all(sample.labels.get(label) for label in required):
                continue
            host = sample.labels[TELEGRAF_HOST_LABEL]
            resource = resources.setdefault(
                host, ResourceInfoData(type=RESOURCE_TYPE_NODE, name=host)
            )
            families = self._host_families.setdefault(host, _HostFamilies())
            self._register_sample(family.name, sample, resource, families)

    def _register_sample(
        self,
        family_name: str,
        sample: Sample,
        resource: ResourceInfoData,
        families: _HostFamilies,
    ):
        """Register the information of a single sample at its resource."""
        required = FAMILY_LABELS[family_name]
        path = sample.labels.get(TELEGRAF_DISK_PATH_LABEL)
        interface = sample.labels.get(TELEGRAF_NETWORK_INTERFACE_LABEL)
        jail = sample.labels.get(TELEGRAF_FAIL2BAN_JAIL_LABEL)
        # Filesystems
        if TELEGRAF_DISK_PATH_LABEL in required and path:
            families.filesystems.setdefault(path, set()).add(family_name)
            if resource.filesystems is None:
                resource.filesystems = {}
            size = _non_negative(sample.value)
            if family_name == TELEGRAF_DISK_TOTAL and size is not None:
                resource.filesystems[path] = get_appropriate_unit(size)
            else:
                resource.filesystems.setdefault(path, UnitOfInformation.MEGABYTES)
            device = sample.labels.get(TELEGRAF_DISK_DEVICE_LABEL)
            if device:
                if resource.filesystem_devices is None:
                    resource.filesystem_devices = {}
                resource.filesystem_devices[path] = device
        # Network interfaces
        elif TELEGRAF_NETWORK_INTERFACE_LABEL in required and interface:
            families.interfaces.setdefault(interface, set()).add(family_name)
            if resource.network_interfaces is None:
                resource.network_interfaces = set()
            resource.network_interfaces.add(interface)
        # Fail2ban jails
        elif TELEGRAF_FAIL2BAN_JAIL_LABEL in required and jail:
            families.jails.setdefault(jail, set()).add(family_name)
            if resource.jails is None:
                resource.jails = set()
            resource.jails.add(jail)
        # Host
        else:
            families.host.add(family_name)
            # Swap size of zero means swap is not configured
            if family_name == TELEGRAF_SWAP_TOTAL and sample.value == 0:
                families.host.add(_SWAP_UNCONFIGURED)

    @staticmethod
    def _host_metrics(families: set[str]) -> set[str]:
        """Derive supported host metric keys from the available families."""
        has_mem_total = TELEGRAF_MEM_TOTAL in families
        has_swap = _SWAP_UNCONFIGURED not in families
        conditions = {
            METRIC_CPU_USAGE_PCT: TELEGRAF_CPU_USAGE_IDLE in families,
            METRIC_MEMORY_USAGE_PCT: TELEGRAF_MEM_USED_PERCENT in families
            or (
                has_mem_total
                and (
                    TELEGRAF_MEM_USED in families or TELEGRAF_MEM_AVAILABLE in families
                )
            ),
            METRIC_MEMORY_USAGE_BYTES: TELEGRAF_MEM_USED in families
            or (has_mem_total and TELEGRAF_MEM_AVAILABLE in families),
            METRIC_SWAP_USAGE_PCT: has_swap
            and (
                TELEGRAF_SWAP_USED_PERCENT in families
                or (TELEGRAF_SWAP_TOTAL in families and TELEGRAF_SWAP_USED in families)
            ),
            METRIC_SWAP_USAGE_BYTES: has_swap and TELEGRAF_SWAP_USED in families,
            METRIC_UPTIME_SECONDS: TELEGRAF_SYSTEM_UPTIME in families,
            METRIC_LOAD_AVERAGE_1M: TELEGRAF_SYSTEM_LOAD1 in families,
            METRIC_LOAD_AVERAGE_5M: TELEGRAF_SYSTEM_LOAD5 in families,
            METRIC_LOAD_AVERAGE_15M: TELEGRAF_SYSTEM_LOAD15 in families,
        }
        return {metric for metric, available in conditions.items() if available}

    @staticmethod
    def _filesystem_metrics(families: set[str]) -> set[str]:
        """Derive supported metric keys of a single filesystem."""
        has_total = TELEGRAF_DISK_TOTAL in families
        conditions = {
            METRIC_DISK_USAGE_PCT: TELEGRAF_DISK_USED_PERCENT in families
            or (
                has_total
                and (TELEGRAF_DISK_USED in families or TELEGRAF_DISK_FREE in families)
            ),
            METRIC_DISK_USAGE_BYTES: TELEGRAF_DISK_USED in families
            or (has_total and TELEGRAF_DISK_FREE in families),
        }
        return {metric for metric, available in conditions.items() if available}

    @staticmethod
    def _interface_metrics(families: set[str]) -> set[str]:
        """Derive supported metric keys of a single network interface."""
        conditions = {
            METRIC_NETWORK_RECEIVE_BYTES: TELEGRAF_NET_BYTES_RECV in families,
            METRIC_NETWORK_TRANSMIT_BYTES: TELEGRAF_NET_BYTES_SENT in families,
        }
        return {metric for metric, available in conditions.items() if available}

    @staticmethod
    def _jail_metrics(families: set[str]) -> set[str]:
        """Derive supported metric keys of a single Fail2ban jail."""
        conditions = {
            METRIC_FAIL2BAN_BANNED: TELEGRAF_FAIL2BAN_BANNED in families,
            METRIC_FAIL2BAN_FAILED: TELEGRAF_FAIL2BAN_FAILED in families,
        }
        return {metric for metric, available in conditions.items() if available}

    def _fail2ban_total_metrics(self, jails: dict[str, set[str]]) -> set[str]:
        """Derive the host totals, which require the metric from every jail."""
        if not jails:
            return set()
        jail_metrics = [self._jail_metrics(families) for families in jails.values()]
        return {
            total_key
            for key, total_key in FAIL2BAN_TOTALS.items()
            if all(key in metrics for metrics in jail_metrics)
        }

    def _resource_metrics(self, families: _HostFamilies) -> set[str]:
        """Derive all supported metric keys of a host from its own families."""
        metrics = self._host_metrics(families.host)
        for interface_families in families.interfaces.values():
            metrics |= self._interface_metrics(interface_families)
        for filesystem_families in families.filesystems.values():
            metrics |= self._filesystem_metrics(filesystem_families)
        for jail_families in families.jails.values():
            metrics |= self._jail_metrics(jail_families)
        metrics |= self._fail2ban_total_metrics(families.jails)
        return metrics

    def _update_supported_metrics(self, available_metrics: list[str]):
        """Set the supported metrics to the union of the per-host results."""
        supported: set[str] = set()
        for families in self._host_families.values():
            supported |= self._resource_metrics(families)
        # Recalculated from scratch, so the result is independent of family order
        available_metrics[:] = [m for m in SUPPORTED_METRIC_ORDER if m in supported]

    def collect_supported_metric(self, family: Metric, available_metrics: list[str]):
        """Collect supported metrics, evaluated independently for each host."""
        self._update_supported_metrics(available_metrics)

    def post_process_resources(self, resources: dict) -> dict[str, ResourceInfoData]:
        """Assign the available metrics to each resource."""
        for host, resource in resources.items():
            families = self._host_families.get(host, _HostFamilies())
            resource.available_metrics = self._resource_metrics(families)
            resource.interface_metrics = {
                interface: self._interface_metrics(interface_families)
                for interface, interface_families in families.interfaces.items()
            }
            resource.filesystem_metrics = {
                path: self._filesystem_metrics(path_families)
                for path, path_families in families.filesystems.items()
            }
            resource.jail_metrics = {
                jail: self._jail_metrics(jail_families)
                for jail, jail_families in families.jails.items()
            }
        # Reset state to start with a clean state on next metadata extraction
        self._host_families = {}
        return resources

    # Metric extraction
    def get_metric_key(self, sample_name: str) -> str:
        """Return metric key, preserving Telegraf names ending with '_total'."""
        if sample_name in FAMILY_LABELS:
            return sample_name
        # Counters are munged by the parser to end with "_total"
        stripped = sample_name.removesuffix("_total")
        return stripped if stripped in FAMILY_LABELS else sample_name

    def prepare_metric_value(self, metric_key: str, sample: Sample) -> float | dict:
        """Override: Collect metric value."""
        if metric_key.startswith("cpu_"):
            return {sample.labels[TELEGRAF_CPU_LABEL]: sample.value}
        if metric_key.startswith("disk_"):
            return {sample.labels[TELEGRAF_DISK_PATH_LABEL]: sample.value}
        if metric_key.startswith("net_"):
            return {sample.labels[TELEGRAF_NETWORK_INTERFACE_LABEL]: sample.value}
        if metric_key.startswith("fail2ban_"):
            return {sample.labels[TELEGRAF_FAIL2BAN_JAIL_LABEL]: sample.value}
        return sample.value

    def _pre_process_metrics(self, metrics: dict):
        """Forget measurements of hosts that are no longer exposed."""
        for resource in list(self._previous_metrics):
            if resource not in metrics:
                del self._previous_metrics[resource]

    def _calculate_resource_metrics(
        self, resource: str, metrics: dict, update_interval: int
    ) -> dict | None:
        """Process resource metrics and return sensor metrics."""
        sensor_metrics = super()._calculate_resource_metrics(
            resource, metrics, update_interval
        )
        sensor_metrics.update(self._calculate_swap_usage(resource, metrics))
        sensor_metrics.update(self._calculate_load_average(resource, metrics))
        sensor_metrics.update(self._calculate_fail2ban(resource, metrics))
        return sensor_metrics

    def _calculate_cpu_usage(
        self, resource: str, metrics: dict, update_interval: int
    ) -> dict[str, Any]:
        """Calculate CPU usage (percentage of non-idle time)."""
        sensor_metrics: dict[str, Any] = {}
        idle = metrics.get(TELEGRAF_CPU_USAGE_IDLE)
        core_count = _non_negative(metrics.get(TELEGRAF_SYSTEM_N_CPUS))
        if isinstance(idle, dict):
            # Prefer the aggregate sample and do not count it among the cores
            total_idle = _percentage(idle.get(TELEGRAF_CPU_TOTAL))
            core_idles = [
                value
                for cpu, raw in idle.items()
                if cpu != TELEGRAF_CPU_TOTAL and (value := _percentage(raw)) is not None
            ]
            usage = None
            if total_idle is not None:
                usage = 100 - total_idle
            elif core_idles:
                usage = sum(100 - value for value in core_idles) / len(core_idles)
            if usage is not None:
                sensor_metrics[METRIC_CPU_USAGE_PCT] = usage
            if core_count is None and core_idles:
                core_count = len(core_idles)
        if core_count:
            sensor_metrics[PROPERTY_CPU_CORES] = int(core_count)
        return sensor_metrics

    def _calculate_memory_usage(self, resource: str, metrics: dict) -> dict[str, Any]:
        """Calculate memory usage (used bytes, used pct)."""
        sensor_metrics: dict[str, Any] = {}
        total = _non_negative(metrics.get(TELEGRAF_MEM_TOTAL))
        used, used_pct = _calculate_usage(
            total,
            _non_negative(metrics.get(TELEGRAF_MEM_USED)),
            _non_negative(metrics.get(TELEGRAF_MEM_AVAILABLE)),
            _percentage(metrics.get(TELEGRAF_MEM_USED_PERCENT)),
        )
        if used is not None:
            sensor_metrics[METRIC_MEMORY_USAGE_BYTES] = used
        if used_pct is not None:
            sensor_metrics[METRIC_MEMORY_USAGE_PCT] = used_pct
        if total:
            sensor_metrics[PROPERTY_MEMORY_SIZE] = _format_size(total)
        return sensor_metrics

    def _calculate_swap_usage(self, resource: str, metrics: dict) -> dict[str, Any]:
        """Calculate swap usage (used bytes, used pct)."""
        sensor_metrics: dict[str, Any] = {}
        total = _non_negative(metrics.get(TELEGRAF_SWAP_TOTAL))
        # Systems without swap do not provide swap sensors
        if total == 0:
            return sensor_metrics
        used, used_pct = _calculate_usage(
            total,
            _non_negative(metrics.get(TELEGRAF_SWAP_USED)),
            None,
            _percentage(metrics.get(TELEGRAF_SWAP_USED_PERCENT)),
        )
        if used is not None:
            sensor_metrics[METRIC_SWAP_USAGE_BYTES] = used
        if used_pct is not None:
            sensor_metrics[METRIC_SWAP_USAGE_PCT] = used_pct
        if total:
            sensor_metrics[PROPERTY_SWAP_SIZE] = _format_size(total)
        return sensor_metrics

    def _calculate_disk_usage(self, resource: str, metrics: dict) -> dict[str, Any]:
        """Calculate disk usage (used bytes, used pct) per mount point."""
        sensor_metrics: dict[str, Any] = {}
        per_path = {
            key: metrics[key] if isinstance(metrics.get(key), dict) else {}
            for key in (
                TELEGRAF_DISK_TOTAL,
                TELEGRAF_DISK_USED,
                TELEGRAF_DISK_FREE,
                TELEGRAF_DISK_USED_PERCENT,
            )
        }
        paths = {path for values in per_path.values() for path in values}
        disk_sizes: dict[str, str] = {}
        for path in paths:
            total = _non_negative(per_path[TELEGRAF_DISK_TOTAL].get(path))
            used, used_pct = _calculate_usage(
                total,
                _non_negative(per_path[TELEGRAF_DISK_USED].get(path)),
                _non_negative(per_path[TELEGRAF_DISK_FREE].get(path)),
                _percentage(per_path[TELEGRAF_DISK_USED_PERCENT].get(path)),
            )
            if used is not None:
                sensor_metrics[f"{METRIC_DISK_USAGE_BYTES}_{path}"] = used
            if used_pct is not None:
                sensor_metrics[f"{METRIC_DISK_USAGE_PCT}_{path}"] = used_pct
            if total:
                disk_sizes[path] = _format_size(total)
        if disk_sizes:
            sensor_metrics[PROPERTY_DISK_SIZE] = disk_sizes
        return sensor_metrics

    def _calculate_network_io(
        self, resource: str, metrics: dict, update_interval: int
    ) -> dict[str, Any]:
        """Calculate network IO (bytes per second) from consecutive counters."""
        sensor_metrics: dict[str, Any] = {}
        now = monotonic()
        previous = self._previous_metrics.setdefault(resource, {})
        rebooted = self._detect_reboot(previous, metrics)
        for source_key, metric_key in (
            (TELEGRAF_NET_BYTES_RECV, METRIC_NETWORK_RECEIVE_BYTES),
            (TELEGRAF_NET_BYTES_SENT, METRIC_NETWORK_TRANSMIT_BYTES),
        ):
            counters = metrics.get(source_key)
            # All baselines are invalid after a reboot of the host
            previous_samples: dict[str, tuple[float, float]] = (
                {} if rebooted else previous.get(source_key, {})
            )
            # Interfaces which are not (validly) exposed lose their baseline
            current_samples: dict[str, tuple[float, float]] = {}
            if isinstance(counters, dict):
                for interface, raw in counters.items():
                    counter = _non_negative(raw)
                    if counter is None:
                        continue
                    current_samples[interface] = (counter, now)
                    prev = previous_samples.get(interface)
                    if prev is None:
                        continue
                    prev_counter, prev_time = prev
                    elapsed = now - prev_time
                    if elapsed < MIN_ELAPSED_SECONDS:
                        # Keep the older baseline to measure over a valid interval
                        current_samples[interface] = prev
                    elif counter >= prev_counter:
                        sensor_metrics[f"{metric_key}_{interface}"] = (
                            counter - prev_counter
                        ) / elapsed
                    # A smaller counter indicates a reset: new baseline, no rate
            previous[source_key] = current_samples
        return sensor_metrics

    @staticmethod
    def _detect_reboot(previous: dict, metrics: dict) -> bool:
        """Detect a host reboot by a decreasing uptime.

        An unchanged uptime is not a reboot, as Telegraf may expose cached samples.
        Without a valid uptime nothing is detected.
        """
        uptime = _valid_uptime(metrics.get(TELEGRAF_SYSTEM_UPTIME))
        if uptime is None:
            return False
        previous_uptime = previous.get(TELEGRAF_SYSTEM_UPTIME)
        previous[TELEGRAF_SYSTEM_UPTIME] = uptime
        return previous_uptime is not None and uptime < previous_uptime

    def _calculate_uptime(self, resource: str, metrics: dict) -> dict[str, Any]:
        """Calculate uptime and derive the last start time."""
        sensor_metrics: dict[str, Any] = {}
        uptime = _valid_uptime(metrics.get(TELEGRAF_SYSTEM_UPTIME))
        if uptime is not None:
            sensor_metrics[METRIC_UPTIME_SECONDS] = int(uptime)
            sensor_metrics[PROPERTY_LAST_START_TIME] = (
                dt_util.utcnow() - timedelta(seconds=uptime)
            ).replace(microsecond=0)
        return sensor_metrics

    def _calculate_load_average(self, resource: str, metrics: dict) -> dict[str, Any]:
        """Collect the 1, 5 and 15 minute load averages."""
        sensor_metrics: dict[str, Any] = {}
        for source_key, metric_key in (
            (TELEGRAF_SYSTEM_LOAD1, METRIC_LOAD_AVERAGE_1M),
            (TELEGRAF_SYSTEM_LOAD5, METRIC_LOAD_AVERAGE_5M),
            (TELEGRAF_SYSTEM_LOAD15, METRIC_LOAD_AVERAGE_15M),
        ):
            load = _non_negative(metrics.get(source_key))
            if load is not None:
                sensor_metrics[metric_key] = load
        return sensor_metrics

    def _calculate_fail2ban(self, resource: str, metrics: dict) -> dict[str, Any]:
        """Collect the Fail2ban gauges per jail and their sums per host.

        The values are plain gauges, so no rates are calculated. A host total is
        only provided if every jail of the host has a valid value; otherwise it
        would be a misleading partial sum.
        """
        sensor_metrics: dict[str, Any] = {}
        values = {
            key: metrics[key] if isinstance(metrics.get(key), dict) else {}
            for key in (TELEGRAF_FAIL2BAN_BANNED, TELEGRAF_FAIL2BAN_FAILED)
        }
        jails = {jail for per_jail in values.values() for jail in per_jail}
        for source_key, metric_key in (
            (TELEGRAF_FAIL2BAN_BANNED, METRIC_FAIL2BAN_BANNED),
            (TELEGRAF_FAIL2BAN_FAILED, METRIC_FAIL2BAN_FAILED),
        ):
            counts = {jail: _count(values[source_key].get(jail)) for jail in jails}
            for jail, count in counts.items():
                if count is not None:
                    sensor_metrics[f"{metric_key}_{jail}"] = count
            valid = [count for count in counts.values() if count is not None]
            if valid and len(valid) == len(counts):
                sensor_metrics[FAIL2BAN_TOTALS[metric_key]] = sum(valid)
        return sensor_metrics
