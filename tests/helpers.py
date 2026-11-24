"""Helpers for the OpenMetrics tests."""

import re
from pathlib import Path

from custom_components.openmetrics.metrics.processor import OpenMetricsProcessor

FIXTURE_DIR = Path(__file__).parent / "fixtures"
CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


def load_fixture(name: str) -> str:
    """Return the text of a fixture file."""
    return (FIXTURE_DIR / name).read_text()


def get_metadata(text: str, processor: OpenMetricsProcessor | None = None):
    """Extract metadata from exposition text."""
    processor = processor or OpenMetricsProcessor()
    return processor.extract_metadata(processor.parse_data(text, CONTENT_TYPE))


def poll(processor: OpenMetricsProcessor, text: str, interval: int = 10) -> dict:
    """Run one polling cycle (parse, extract, process) and return sensor data."""
    families = processor.parse_data(text, CONTENT_TYPE)
    metrics = processor.extract_metrics(families, [])
    return processor.process_metrics(metrics, interval)


class FakeClock:
    """Controllable replacement for time.monotonic."""

    def __init__(self, now: float = 1000.0) -> None:
        """Initialize the clock."""
        self.now = now

    def __call__(self) -> float:
        """Return the current fake time."""
        return self.now


def set_value(text: str, selector: str, value: str) -> str:
    """Replace the value of all samples whose line starts with selector."""
    return re.sub(
        rf"^({re.escape(selector)}[^\n]*\}} )\S+$",
        rf"\g<1>{value}",
        text,
        flags=re.MULTILINE,
    )


def remove_samples(text: str, name: str) -> str:
    """Remove all lines belonging to a metric family."""
    return "\n".join(
        line
        for line in text.splitlines()
        if not re.match(rf"^(# (HELP|TYPE) )?{name}[{{ ]", line)
    )
