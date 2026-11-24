"""Data classes for metrics."""

from dataclasses import dataclass
from typing import Any


@dataclass
class ProviderInfoData:
    """Provider information data."""

    name: str
    type: str
    version: str | None = None


@dataclass
class ResourceInfoData:
    """Resource information data."""

    type: str
    name: str | None = None
    software: str | None = None
    version: str | None = None
    model: str | None = None
    serial_number: str | None = None
    is_virtual: bool = False
    via_resource: str | None = None
    network_interfaces: set[str] | None = None
    filesystems: dict[str, Any] | None = None
    filesystem_devices: dict[str, str] | None = None
    # Fail2ban jails of the resource
    jails: set[str] | None = None
    # Metric keys available for this resource (None = no per-resource restriction)
    available_metrics: set[str] | None = None
    # Metric keys available per network interface / filesystem (None = unrestricted)
    interface_metrics: dict[str, set[str]] | None = None
    filesystem_metrics: dict[str, set[str]] | None = None
    # Metric keys available per Fail2ban jail (None = unrestricted)
    jail_metrics: dict[str, set[str]] | None = None


@dataclass
class MetadataData:
    """Metadata for metrics providers."""

    provider_info: ProviderInfoData
    resources: dict[str, ResourceInfoData]
    available_metrics: list[str]
