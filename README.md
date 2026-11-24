# OpenMetrics Home Assistant Integration

[![GitHub Release](https://img.shields.io/github/release/txxa/hass-openmetrics.svg?style=for-the-badge)](https://github.com/txxa/hass-openmetrics/releases)
[![GitHub Activity](https://img.shields.io/github/commit-activity/y/txxa/hass-openmetrics.svg?style=for-the-badge)](https://github.com/txxa/hass-openmetrics/commits/main)
[![License](https://img.shields.io/github/license/txxa/hass-openmetrics.svg?style=for-the-badge)](https://github.com/txxa/hass-openmetrics/blob/main/LICENSE)
[![HACS](https://img.shields.io/badge/HACS-Custom-orange.svg?style=for-the-badge)](https://hacs.xyz/docs/faq/custom_repositories)

_Integration to integrate with OpenMetrics and Prometheus exposition format providers._

The [OpenMetrics specification](https://github.com/OpenObservability/OpenMetrics/blob/main/specification/OpenMetrics.md) defines a standard for exposing metrics in a text-based format. This integration supports both the OpenMetrics format and the Prometheus exposition format, which is a widely adopted format for exposing metrics. The library used to process the data is coming from the [Python client repository](https://github.com/prometheus/client_python/blob/master/prometheus_client/) of Prometheus.

Example applications that provide metrics data in supported formats:
- [Prometheus](https://prometheus.io/)
- [Thanos](https://thanos.io/)
- [Cortex](https://cortexmetrics.io/)
- [Node Exporter](https://github.com/prometheus/node_exporter)
- [cAdvisor](https://github.com/google/cadvisor)
- [Blackbox Exporter](https://github.com/prometheus/blackbox_exporter)

This integration allows you to monitor various metrics from OpenMetrics and Prometheus exposition format providers within Home Assistant.

## Table of contents

- [Features](#features)
- [Installation](#installation)
- [Configuration](#configuration)
- [Telegraf](#telegraf)
- [Compatibility](#compatibility)
- [Development and Maintenance](#development-and-maintenance)
- [Contributions](#contributions)

## Features

- Monitor CPU, memory, disk, network, and uptime metrics of hosts and containers.
- Support for multiple metrics providers (Node Exporter, cAdvisor, Telegraf).
- Multi-container support for container metrics providers.
- Basic authentication support.
- SSL/TLS support.
- Dynamic sources management for multi-container metrics providers.
- Dynamic metrics management.
- Configurable scan interval for sensor data updates.

## Installation

1. Add this repository as a custom repository to HACS: [![Add Repository](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=txxa&repository=hass-openmetrics&category=integration)
2. Use HACS to install the integration.
3. Restart Home Assistant.
4. Set up the integration using the UI: [![Add Integration](https://my.home-assistant.io/badges/config_flow_start.svg)](https://my.home-assistant.io/redirect/config_flow_start/?domain=openmetrics)

## Configuration

Configuration is done through the Home Assistant UI.

### Initial Setup

To add the integration, go to Settings ➤ Devices & Services ➤ Integrations, click ➕ Add Integration, and search for "OpenMetrics".

The initial setup requests the following information:

- **Provider URL**: The URL of the metrics provider.
- **Username**: The username for the metrics provider web interface.
- **Password**: The password for the metrics provider web interface.
- **Verify SSL certificate**: Whether to verify the SSL certificate of the metrics provider.

### Options

Find configuration options under Settings ➤ Devices & Services ➤ Integrations ➤ OpenMetrics ➤ Configure.

The following options can be configured after the initial setup:

- **Resources to monitor**: The resources to monitor.
- **Metrics to collect**: The metrics to collect.
- **Scan interval [s]**: The interval at which to gather the metrics.

## Telegraf

Telegraf is supported natively through its Prometheus output (`outputs.prometheus_client`). One HTTP request per configured endpoint and polling cycle is used.

### Detection

The provider is detected automatically from the metric families and labels Telegraf's input plugins produce. Explicit Node Exporter and cAdvisor identifiers always take precedence. An endpoint is recognized as Telegraf if it exposes, with the required labels (`host`, plus `cpu`, `path`, `interface` or `jail` where applicable), either

- at least three of the supported families listed below, or
- one of these combinations on the same host: `net_bytes_recv` + `net_bytes_sent`, `mem_used_percent` + `mem_total`, `swap_used_percent` + `swap_total`, `disk_used_percent` + `disk_total`, `fail2ban_banned` + `fail2ban_failed`.

Minimal configurations such as a network-only, memory-only or Fail2ban-only Telegraf are therefore detected, but an endpoint which only exposes e.g. `system_load1` and `system_uptime` is not.

### Telegraf configuration

```toml
[[inputs.cpu]]
  percpu = true
  totalcpu = true
  collect_cpu_time = false
  report_active = false

[[inputs.mem]]
[[inputs.swap]]
[[inputs.disk]]
  ignore_fs = ["tmpfs", "devtmpfs", "devfs", "iso9660", "overlay", "aufs", "squashfs"]
[[inputs.net]]
[[inputs.system]]
# Optional, requires fail2ban-client access for the Telegraf user
[[inputs.fail2ban]]
  use_sudo = true

[[outputs.prometheus_client]]
  listen = ":9273"
  metric_version = 2
  path = "/metrics"
```

Required input plugins depend on the sensors you want: `cpu` (`totalcpu = true` is recommended, per-core values are used as a fallback), `mem`, `swap`, `disk`, `net`, `system` and `fail2ban` (optional). Do not set `omit_hostname = true`: hosts are identified by Telegraf's `host` tag. Additional tags (e.g. `location`) are ignored. Any number of hosts can be exposed through one endpoint.

### Home Assistant setup

Add the integration and use the Telegraf metrics URL (e.g. `http://telegraf.example.com:9273/metrics`). Select the hosts to monitor, then the metrics. Filesystems (`path` label), network interfaces (`interface` label, any valid Linux name such as `wg-home`) and Fail2ban jails (`jail` label) are discovered dynamically. Sensors are only offered and created if the required Telegraf metrics exist for the same host, filesystem, interface or jail.

### Supported Telegraf metrics

| Telegraf metric                                              | Entity (attributes)                                                                       |
| :----------------------------------------------------------- | :---------------------------------------------------------------------------------------- |
| `cpu_usage_idle`, `system_n_cpus`                            | CPU usage in % (`100 - idle` of `cpu="cpu-total"`, otherwise the per-core average); attribute `cpu_cores` |
| `mem_used_percent`, `mem_used`, `mem_total`, `mem_available` | Memory usage in % and in bytes; attribute `memory_size`                                   |
| `swap_used_percent`, `swap_used`, `swap_total`               | Swap usage in % and in bytes, not offered for hosts without swap; attribute `swap_size`   |
| `disk_used_percent`, `disk_used`, `disk_free`, `disk_total`  | Filesystem usage in % and bytes per mount point; attributes `disk_size` and `disk_device` |
| `net_bytes_recv`, `net_bytes_sent`                           | Network receive/transmit rate per interface                                               |
| `system_uptime`                                              | Uptime in seconds; attribute `last_start_time`                                            |
| `system_load1`, `system_load5`, `system_load15`              | Load averages (not percentages)                                                           |
| `fail2ban_banned`, `fail2ban_failed`                         | Fail2ban *Currently banned* and *Currently failed* per jail, plus the *(total)* sensors per host |

Values are used directly where Telegraf provides them (percentages in the range 0..100, small rounding errors are clamped) and calculated from the byte values otherwise (e.g. `mem_total - mem_available`).

### Fail2ban

The `fail2ban_banned` and `fail2ban_failed` gauges of Telegraf's `inputs.fail2ban` are exposed per jail (labels `host` and `jail`) and as a total per host:

- *Fail2ban – Currently banned (&lt;jail&gt;)* and *Fail2ban – Currently failed (&lt;jail&gt;)* for each discovered jail.
- *Fail2ban – Currently banned (total)* and *Fail2ban – Currently failed (total)* per host. These are the **sum over the jails**, not the number of unique IP addresses (an address banned in two jails is counted twice).

The values are gauges with the state class `measurement`; they can rise and fall and no rates are calculated. Only finite, non-negative integers are accepted (e.g. `5`, `5.0`, `5e0`). A missing or invalid value makes the sensor *unknown*, never `0`. A total is only provided if every jail of the host has a valid value for that metric, so there are never misleading partial sums. Jail and total sensors can be selected independently as metrics.

### Known limitations

- Network rates are the difference between two consecutive counter samples divided by the actual time between the two measurements. Telegraf only refreshes its samples at its own collection `interval` and the exporter serves cached samples in between. Polling faster than that, or at an interval that is not a multiple of it, results in uneven instantaneous estimates (alternating 0 and peaks). Set the scan interval to at least the Telegraf `interval`.
- A rate of `0` is a valid measurement (no traffic, or unchanged cached counters). No value (the sensor shows *unknown*) is exposed for the first sample after startup, after a counter reset, after a host reboot (detected by decreasing counters or a decreasing `system_uptime`), for interfaces which just (re)appeared, and for invalid measurements (NaN/infinite, negative or out of range values). Invalid values are never replaced by zero.
- Without `system_uptime` a reboot is only detected by decreasing counters.
- Samples without a `host` tag (or without a `jail` tag for Fail2ban) are not discovered.
- Fail2ban totals are not offered for hosts on which not every jail exposes both families; the per-jail sensors still are.
- Metadata (hosts, filesystems, interfaces) is read when the integration is set up or reconfigured. Reload the integration or open its options after adding hosts, filesystems or interfaces.
- If the endpoint cannot be reached, the entities of all providers become *unavailable* and recover automatically with the next successful poll (see the coordinator note in the development section).

## Compatibility

This integration has been tested with specific versions of metrics providers. To ensure proper functionality, please use the version of this integration that corresponds to your installed metrics providers.

Refer to the compatibility matrix below:

| Integration | Node Exporter | cAdvisor   |
| :---------- | :------------ | :--------- |
| v0.1.x      | 1.8.2        | 0.49.1    |
| v0.2.0      | 1.8.2        | 0.49.1    |
| v0.3.x      | 1.8.2<br>1.9.1        | 0.49.1<br>0.52.1    |

**Important notes:**

- The integration may work with versions of metrics providers not listed here, but these combinations have not been explicitly tested.
- It is recommended to use the most recent integration version compatible with your metrics provider version.
- If you encounter any issues with untested version combinations, please report them in the [Issues](../../issues) section of this repository.

For the best experience, try to keep both the integration and metrics providers updated to their latest compatible versions.

## Development and maintenance

I basically created this integration for my personal purpose. As it fulfils all my current needs I won't develop it further for now.\
However, as long as I am using this integration in my Home Assistant setup I will maintain it actively.

## Running the tests

The tests require **Python 3.13** (Home Assistant 2025.12 needs ≥ 3.13.2). `requirements_test.txt` is standalone and pins a mutually compatible set (`pytest-homeassistant-custom-component` brings Home Assistant 2025.12.4 and pytest 9), so no manual overrides are needed:

```bash
python3.13 -m venv .venv && source .venv/bin/activate
pip install -r requirements_test.txt
pytest
ruff check . && ruff format . --check
```

Polling failures raise `UpdateFailed` in the coordinator (for all providers) so that entities become unavailable during an outage and recover automatically; unexpected errors are logged with a traceback.

## Contributions

If you want to contribute to this integration, please read the [Contribution guidelines](CONTRIBUTING.md)

### Providing translations for other languages

If you would like to use the integration in another language, you can help out by providing the necessary translations in [custom_components/openmetrics/translations/](./custom_components/openmetrics/translations/) and open a pull request with the changes.
