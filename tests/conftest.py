"""Fixtures for the OpenMetrics tests."""

from unittest.mock import patch

import pytest

from .helpers import FakeClock, load_fixture

CLOCK = "custom_components.openmetrics.providers.telegraf.monotonic"


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    """Enable loading of the custom integration in all tests."""


@pytest.fixture
def sweh00() -> str:
    """Return the representative single host exposition."""
    return load_fixture("telegraf_sweh00.prom")


@pytest.fixture
def multi_host() -> str:
    """Return the multi host exposition (untyped, per-core CPU)."""
    return load_fixture("telegraf_multi_host.prom")


@pytest.fixture
def clock():
    """Patch the clock used for rate calculations."""
    fake_clock = FakeClock()
    with patch(CLOCK, fake_clock):
        yield fake_clock
