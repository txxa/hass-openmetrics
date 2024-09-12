"""Class for interacting with OpenMetrics."""

import logging
from collections.abc import Iterable
from http import HTTPStatus

import aiohttp
from homeassistant.exceptions import HomeAssistantError

from custom_components.openmetrics.lib.metrics_core import Metric

from .const import (
    CADVISOR_VERSION_INFO,
    CONTAINER_METRICS,
    CONTAINER_START_TIME,
    NODE_CPU_IDLE_SECONDS,
    NODE_EXPORTER_BUILD_INFO,
    NODE_METRICS,
    NODE_OS_INFO,
    NODE_UNAME_INFO,
    PROVIDER_NAME_CADVISOR,
    PROVIDER_NAME_NODE_EXPORTER,
    PROVIDER_TYPE_CONTAINER,
    PROVIDER_TYPE_NODE,
    RESOURCE_TYPE_CONTAINER,
    RESOURCE_TYPE_NODE,
)
from .lib import parser, prom_parser

# # Set log level for aiohttp
# aiohttp_logger = logging.getLogger("aiohttp")
# aiohttp_logger.setLevel(logging.DEBUG)

# # Add a console handler for aiohttp logging
# console_handler = logging.StreamHandler()
# console_handler.setLevel(logging.DEBUG)
# aiohttp_logger.addHandler(console_handler)

_LOGGER = logging.getLogger(__name__)


class ProcessingError(HomeAssistantError):
    """Error to indicate a client processing error."""


class RequestError(HomeAssistantError):
    """Error to indicate a client request error."""


class InvalidAuthError(HomeAssistantError):
    """Error to indicate there is invalid auth."""


class CannotConnectError(HomeAssistantError):
    """Error to indicate we cannot connect."""


class OpenMetricsClient:
    """Class for interacting with OpenMetrics."""

    def __init__(
        self,
        url: str,
        verify_ssl: bool,
        username=None,
        password=None,
    ) -> None:
        """Initialize the OpenMetrics client."""
        self.url = url
        self.verify_ssl = verify_ssl
        self.username = username
        if password is not None:
            self.password = str(password)
        self.is_node_metrics_provider = False
        self.is_container_metrics_provider = False
        self.node_metric_keys = self._get_metric_keys(NODE_METRICS)
        self.container_metric_keys = self._get_metric_keys(CONTAINER_METRICS)

    def _get_metric_filters(self, metric_definitions: dict) -> dict:
        """Get metric filters."""
        metric_filters = {}
        for metric_data in metric_definitions.values():
            for metric_key, metric_filter in metric_data.items():
                if metric_key not in metric_filters:
                    metric_filters[metric_key] = metric_filter
        return metric_filters

    def _get_metric_keys(self, metric_definitions: dict) -> dict:
        """Get metric keys."""
        # return [key for metric in metric_definitions.values() for key in metric]
        metric_keys = {}
        for metric_name, metric_definition in metric_definitions.items():
            for metric_key in metric_definition:
                if metric_key not in metric_keys:
                    metric_keys[metric_key] = []
                metric_keys[metric_key].append(metric_name)
        return metric_keys

    async def _make_request(
        self,
        session: aiohttp.ClientSession,
        method: str,
        url: str,
        headers: dict | None = None,
        data: dict | None = None,
    ) -> aiohttp.ClientResponse:
        """Make an HTTP request."""
        return await session.request(
            method, url, headers=headers, data=data, verify_ssl=self.verify_ssl
        )

    async def _async_request_data(self) -> tuple[str, str | None]:
        """Request data from metrics provider."""
        async with aiohttp.ClientSession() as session:
            # Set headers
            headers = {"Accept": "application/openmetrics-text;charset=utf-8"}
            if self.username is not None and self.password is not None:
                auth = aiohttp.BasicAuth(self.username, self.password)
                headers = {"Authorization": auth.encode()}
            try:
                # Make request
                response = await self._make_request(session, "GET", self.url, headers)
            except aiohttp.ClientConnectionError as e:
                raise CannotConnectError(str(e)) from e
            except aiohttp.ClientError as e:
                raise RequestError(str(e)) from e
            else:
                if response.status == HTTPStatus.OK.value:
                    # Read the response
                    response_text = await response.text()
                    content_type = response.headers.get("Content-Type")
                    _LOGGER.debug("Metrics successfully fetched")
                    return (response_text, content_type)
                if response.status == HTTPStatus.UNAUTHORIZED.value:
                    exception_message = f"Invalid auth for {self.url}"
                    raise InvalidAuthError(exception_message)
                exception_message = f"Request failed with status code '{response.status}' and reason '{response.reason}"
                raise RequestError(exception_message)

    def _parse_data(
        self, response_text: str, content_type: str | None
    ) -> Iterable[Metric]:
        """Parse metrics provider data."""
        try:
            if content_type is not None and "text/plain" in content_type:
                families = prom_parser.text_string_to_metric_families(response_text)
            elif (
                content_type is not None
                and "application/openmetrics-text" in content_type
            ):
                families = parser.text_string_to_metric_families(response_text)
            else:
                exception_message = f"Content type '{content_type}' not supported"
                raise ProcessingError(exception_message)
        except Exception as e:
            raise ProcessingError(str(e)) from e
        else:
            _LOGGER.debug("Metrics successfully parsed")
            return families

    def _extract_provider_metadata(self, family, output):
        """Extract provider metadata."""
        if family.name == NODE_EXPORTER_BUILD_INFO:
            provider = PROVIDER_NAME_NODE_EXPORTER
            for sample in family.samples:
                os_version = sample.labels["version"]
                break
            output["provider"] = {
                "name": provider,
                "type": PROVIDER_TYPE_NODE,
                "version": os_version,
            }
            self.is_node_metrics_provider = True
            return True
        if family.name == CADVISOR_VERSION_INFO:
            provider = PROVIDER_NAME_CADVISOR
            for sample in family.samples:
                os_version = sample.labels["cadvisorVersion"]
                break
            output["provider"] = {
                "name": provider,
                "type": PROVIDER_TYPE_CONTAINER,
                "version": os_version,
            }
            self.is_container_metrics_provider = True
            return True
        return False

    def _extract_node_metadata(self, family, output):
        """Extract node metadata."""
        if len(output["resources"]) == 0:
            output["resources"].append({})
        if family.name == NODE_UNAME_INFO:
            for sample in family.samples:
                nodename = sample.labels.get("nodename", None)
                if nodename:
                    output["resources"][0]["type"] = RESOURCE_TYPE_NODE
                    output["resources"][0]["name"] = nodename
                break
        elif family.name == NODE_OS_INFO:
            for sample in family.samples:
                node_os = sample.labels.get("pretty_name", None)
                if node_os:
                    output["resources"][0]["software"] = node_os
                os_version = sample.labels.get("version", None)
                if os_version:
                    output["resources"][0]["version"] = os_version
                break
        if family.name in self.node_metric_keys:
            metric_name = self.node_metric_keys[family.name]
            for metric in metric_name:
                if metric not in output["metrics"]:
                    output["metrics"].append(metric)

    def _extract_container_metadata(self, family, output):
        """Extract container metadata."""
        if family.name == CONTAINER_START_TIME:
            for sample in family.samples:
                name = sample.labels.get("name", None)
                if name is not None and name != "":
                    container_name = name
                    container_image = sample.labels.get("image", "")
                    image_version = sample.labels.get(
                        "container_label_org_opencontainers_image_version", ""
                    )
                    output["resources"].append(
                        {
                            "type": RESOURCE_TYPE_CONTAINER,
                            "name": container_name,
                            "software": container_image,
                            "version": image_version,
                        }
                    )
        if family.name in self.container_metric_keys:
            metric_name = self.container_metric_keys[family.name]
            for metric in metric_name:
                if metric not in output["metrics"]:
                    output["metrics"].append(metric)

    def _extract_metadata(self, families: Iterable[Metric]) -> dict:
        """Extract metadata."""
        try:
            output = {
                "provider": {},
                "resources": [],
                "metrics": [],
            }
            provider_metadata_extracted = False
            for family in families:
                # Extract provider metadata
                if provider_metadata_extracted is False:
                    provider_metadata_extracted = self._extract_provider_metadata(
                        family, output
                    )
                # Extract node metadata
                if self.is_node_metrics_provider or "node_" in family.name:
                    self._extract_node_metadata(family, output)
                # Extract container metadata
                elif self.is_container_metrics_provider or "container_" in family.name:
                    self._extract_container_metadata(family, output)

            if len(output["resources"]) == 0:
                raise ProcessingError("No resources found")
            if len(output["metrics"]) == 0:
                raise ProcessingError("No metrics found")
        except Exception as e:
            raise ProcessingError(str(e)) from e
        else:
            if not output["provider"]:
                exception_message = "Metadata extraction failed"
                raise ProcessingError(exception_message)
            _LOGGER.debug("Metadata successfully extracted")
            return output

    def _sample_matches_resource(self, sample, resource, metrics, family_name):
        """Check if sample is related to resource."""
        # Check if metric filter is empty
        is_label_filter_empty = len(metrics[family_name]) == 0
        # Check if sample has no labels
        is_sample_labelless = len(sample.labels) == 0
        # Process sample if label filter is empty or sample has no labels
        if is_label_filter_empty or is_sample_labelless:
            return True
        # Check if metric is related to resource
        is_sample_of_resource = False
        if "name" in sample.labels:
            is_sample_of_resource = resource in sample.labels["name"]
        elif self.is_node_metrics_provider:
            is_sample_of_resource = True
        # Process sample if sample belongs to resource
        if is_sample_of_resource:
            has_all_labels = True
            # Check all predefined metric labels
            for metric_label in metrics[family_name]:
                # Filter by predefined metric label key
                if metric_label in sample.labels:
                    # Filter by predefined metric label value
                    if metrics[family_name][metric_label] == "*":
                        if sample.labels[metric_label] == "":
                            has_all_labels = False
                            break
                    elif (
                        metrics[family_name][metric_label]
                        != sample.labels[metric_label]
                    ):
                        has_all_labels = False
                        break
                else:
                    has_all_labels = False
                    break
            return has_all_labels
        return False

    def _extract_metric_value(self, sample, family_name, output, resource):
        """Extract metric value."""
        cpu = ""
        if family_name == NODE_CPU_IDLE_SECONDS:
            cpu = sample.labels["cpu"]
            if family_name not in output[resource]:
                output[resource][family_name] = {}
            output[resource][family_name][cpu] = sample.value
        else:
            output[resource][family_name] = sample.value

    def _extract_metrics(
        self, resources: list[str], families: Iterable[Metric]
    ) -> dict:
        """Extract metrics."""
        output = {}
        try:
            # Define metrics set
            if self.is_node_metrics_provider:
                metrics = self._get_metric_filters(NODE_METRICS)
            elif self.is_container_metrics_provider:
                metrics = self._get_metric_filters(CONTAINER_METRICS)
            else:
                exception_message = "Unknown provider"
                raise ValueError(exception_message)
            # Extract metrics
            for family in families:
                # Filter by metric name
                if family.name in metrics:
                    # Check each collected metric sample
                    for sample in family.samples:
                        # Filter metric by resource
                        for resource in resources:
                            if resource not in output:
                                output[resource] = {}
                            if self._sample_matches_resource(
                                sample, resource, metrics, family.name
                            ):
                                self._extract_metric_value(
                                    sample, family.name, output, resource
                                )
        except Exception as e:
            raise ProcessingError(str(e)) from e
        else:
            if len(output) == 0:
                exception_message = "Metrics extraction failed"
                raise ProcessingError(exception_message)
            _LOGGER.debug("Metrics successfully extracted")
            return output

    async def get_metadata(self) -> dict:
        """Get metadata from a metrics provider."""
        try:
            # Request data
            response_text, content_type = await self._async_request_data()
            # Parse data
            families = self._parse_data(response_text, content_type)
            # Extract metadata
            metadata = self._extract_metadata(families)
        except CannotConnectError as e:
            raise CannotConnectError(str(e)) from e
        except InvalidAuthError as e:
            raise InvalidAuthError(str(e)) from e
        except RequestError as e:
            raise RequestError(str(e)) from e
        except ProcessingError as e:
            raise ProcessingError(str(e)) from e
        except Exception as e:
            raise ProcessingError(str(e)) from e
        else:
            # Return metadata
            _LOGGER.debug("Metadata successfully fetched")
            return metadata

    async def get_metrics(self, resources: list[str]) -> dict:
        """Get metrics from a metrics provider."""
        try:
            # Requst data
            response_text, content_type = await self._async_request_data()
            # Parse data
            families = self._parse_data(response_text, content_type)
            # Extract metrics
            metrics = self._extract_metrics(resources, families)
        except CannotConnectError as e:
            raise CannotConnectError(str(e)) from e
        except InvalidAuthError as e:
            raise InvalidAuthError(str(e)) from e
        except RequestError as e:
            raise RequestError(str(e)) from e
        except ProcessingError as e:
            raise ProcessingError(str(e)) from e
        except Exception as e:
            raise ProcessingError(str(e)) from e
        else:
            # Return metrics
            _LOGGER.debug("Metrics for %s successfully fetched", resources)
            return metrics
