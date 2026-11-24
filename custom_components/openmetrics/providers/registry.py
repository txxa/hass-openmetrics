"""Registry for provider configurations."""

from custom_components.openmetrics.providers.generic import GenericProvider

from ..lib.metrics_core import Metric
from .base import MetricsProvider
from .cadvisor import CADVISOR_VERSION_INFO, CadvisorProvider
from .node_exporter import NODE_EXPORTER_BUILD_INFO, NodeExporterProvider
from .telegraf import TelegrafProvider


class ProviderRegistry:
    """Registry for provider configurations."""

    def __init__(self):
        """Initialize provider registry."""
        self.providers = {
            NODE_EXPORTER_BUILD_INFO: NodeExporterProvider(),
            CADVISOR_VERSION_INFO: CadvisorProvider(),
        }
        # Providers without identifier metric (detected by characteristic metrics)
        self.__signature_providers: list[MetricsProvider] = [TelegrafProvider()]
        self.__default_provider = GenericProvider()

    def get_provider(self, identifier_metric: str) -> MetricsProvider | None:
        """Get provider based on identifier metric."""
        return self.providers.get(identifier_metric)

    def detect_provider(self, families: list[Metric]) -> MetricsProvider | None:
        """Detect provider based on characteristic metric families and labels."""
        for provider in self.__signature_providers:
            if provider.matches_families(families):
                return provider
        return None

    def get_default_provider(self) -> MetricsProvider:
        """Get default provider."""
        return self.__default_provider
