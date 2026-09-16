"""Time-range slicing for Mode B.

LookupEvents pagination tokens expire after roughly 60 minutes. A single
NextToken chain across a 90-day range will therefore die mid-stream, and the
failure is silent in the worst way: you get *some* events and no error that
says the rest are missing. So the range is cut into bounded windows and each
window paginates independently. A window that fails can be retried or reported
without poisoning the rest of the run.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .errors import ConfigError

# CloudTrail's LookupEvents API retains 90 days of management events.
LOOKUP_RETENTION = timedelta(days=90)


@dataclass(frozen=True, slots=True)
class Window:
    """A half-open time window ``[start, end)``."""

    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        if self.start.tzinfo is None or self.end.tzinfo is None:
            raise ConfigError("window bounds must be timezone-aware")
        if self.end <= self.start:
            raise ConfigError(f"window end {self.end} is not after start {self.start}")

    @property
    def duration(self) -> timedelta:
        return self.end - self.start

    def key(self) -> str:
        """Stable identifier used in checkpoint records."""
        return f"{self.start.isoformat()}/{self.end.isoformat()}"


def slice_windows(
    start: datetime,
    end: datetime,
    window: timedelta,
) -> list[Window]:
    """Cut ``[start, end)`` into consecutive windows of at most ``window``.

    Windows are contiguous and non-overlapping, and the final window is clipped
    to ``end`` rather than extending past it — over-running the requested range
    would put events in the evidence set that the engagement scope did not
    authorise collecting.
    """
    if start.tzinfo is None or end.tzinfo is None:
        raise ConfigError(
            "start and end must be timezone-aware; a naive bound would make the "
            "collected range depend on the collector host's local timezone"
        )
    start = start.astimezone(timezone.utc)
    end = end.astimezone(timezone.utc)
    if end <= start:
        raise ConfigError(f"end time {end.isoformat()} must be after start {start.isoformat()}")
    if window <= timedelta(0):
        raise ConfigError(f"window size must be positive, got {window}")

    windows: list[Window] = []
    cursor = start
    while cursor < end:
        stop = min(cursor + window, end)
        windows.append(Window(cursor, stop))
        cursor = stop
    return windows


def warn_if_outside_retention(start: datetime, now: datetime | None = None) -> str | None:
    """Return a warning if the requested start predates LookupEvents retention.

    This is a warning rather than an error: an analyst may legitimately request
    a wide range knowing the early part will be empty. But it must be *said*,
    loudly, or an empty early period reads as "nothing happened" instead of
    "the API cannot answer for that period".
    """
    now = now or datetime.now(timezone.utc)
    horizon = now - LOOKUP_RETENTION
    if start < horizon:
        missing = horizon - start
        return (
            f"requested start {start.isoformat()} is {missing.days} day(s) older than "
            f"the LookupEvents 90-day retention horizon ({horizon.isoformat()}). "
            "Events before that horizon CANNOT be retrieved in lookup mode and "
            "their absence is a collection artifact, not evidence of no activity."
        )
    return None
