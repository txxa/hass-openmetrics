# OpenMetrics Home Assistant Integration

[![GitHub Release](https://img.shields.io/github/release/txxa/hass-openmetrics.svg?style=for-the-badge)](https://github.com/txxa/hass-openmetrics/releases)
[![GitHub Activity](https://img.shields.io/github/commit-activity/y/txxa/hass-openmetrics.svg?style=for-the-badge)](https://github.com/txxa/hass-openmetrics/commits/main)
[![License](https://img.shields.io/github/license/txxa/hass-openmetrics.svg?style=for-the-badge)](LICENSE)
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

## Features

- Monitor CPU, memory, disk, network, and uptime metrics of hosts and containers.
- Support for multiple metrics providers.
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

## Development and maintenance

I basically created this integration for my personal purpose. As it fulfils all my current needs I won't develop it further for now.\
However, as long as I am using this integration in my Home Assistant setup I will maintain it actively.

## Contributions are welcome

If you want to contribute to this integration, please read the [Contribution guidelines](CONTRIBUTING.md)

### Providing translations for other languages

If you would like to use the integration in another language, you can help out by providing the necessary translations in [custom_components/openmetrics/translations/](./custom_components/openmetrics/translations/) and open a pull request with the changes.
