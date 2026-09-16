"""Progress reporting for runs that last hours or days.

Written for a terminal session an analyst leaves open overnight: single
rewriting status line when attached to a TTY, periodic plain lines when output
is redirected to a file (so a log of a 30-hour run does not become 400 MB of
carriage returns).
"""

from __future__ import annotations

import sys
import threading
import time
from dataclasses import dataclass


@dataclass(slots=True)
class _Counters:
    objects: int = 0
    events: int = 0
    bytes_: int = 0
    failures: int = 0


class Progress:
    """Thread-safe progress counter with throttled rendering."""

    def __init__(
        self,
        *,
        total_objects: int | None = None,
        total_bytes: int | None = None,
        interval: float = 1.0,
        stream=None,
    ) -> None:
        self._counters = _Counters()
        self._total_objects = total_objects
        self._total_bytes = total_bytes
        self._interval = interval
        self._stream = stream if stream is not None else sys.stdout
        self._lock = threading.Lock()
        self._start = time.monotonic()
        self._last_render = 0.0
        self._tty = hasattr(self._stream, "isatty") and self._stream.isatty()

    def update(self, *, objects: int = 0, events: int = 0, bytes_: int = 0, failures: int = 0) -> None:
        with self._lock:
            self._counters.objects += objects
            self._counters.events += events
            self._counters.bytes_ += bytes_
            self._counters.failures += failures
            now = time.monotonic()
            if now - self._last_render >= self._interval:
                self._last_render = now
                self._render(final=False)

    def finish(self) -> None:
        with self._lock:
            self._render(final=True)
            if self._tty:
                self._stream.write("\n")
            self._stream.flush()

    def _render(self, *, final: bool) -> None:
        elapsed = max(time.monotonic() - self._start, 1e-6)
        counters = self._counters
        rate = counters.objects / elapsed
        line = (
            f"{counters.objects:,} objects"
            + (f"/{self._total_objects:,}" if self._total_objects else "")
            + f"  {_human_bytes(counters.bytes_)}"
            + (f"/{_human_bytes(self._total_bytes)}" if self._total_bytes else "")
            + f"  {rate:,.1f} obj/s"
        )
        if counters.events:
            line += f"  {counters.events:,} events"
        if counters.failures:
            line += f"  {counters.failures:,} FAILED"
        line += f"  elapsed {_human_duration(elapsed)}"

        eta = self._eta(elapsed, rate)
        if eta is not None and not final:
            line += f"  ETA {_human_duration(eta)}"

        if self._tty and not final:
            self._stream.write("\r\033[K" + line)
        else:
            self._stream.write(("\r\033[K" if self._tty else "") + line + "\n")
        self._stream.flush()

    def _eta(self, elapsed: float, rate: float) -> float | None:
        """Estimate remaining time, preferring bytes over object count.

        Object counts are a poor predictor here because CloudTrail objects vary
        by orders of magnitude in size.
        """
        counters = self._counters
        if self._total_bytes and counters.bytes_:
            byte_rate = counters.bytes_ / elapsed
            if byte_rate > 0:
                return max(self._total_bytes - counters.bytes_, 0) / byte_rate
        if self._total_objects and rate > 0:
            return max(self._total_objects - counters.objects, 0) / rate
        return None

    @property
    def objects(self) -> int:
        return self._counters.objects

    @property
    def events(self) -> int:
        return self._counters.events


def _human_bytes(count: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if abs(count) < 1024.0 or unit == "PiB":
            return f"{count:,.1f} {unit}" if unit != "B" else f"{int(count):,} B"
        count /= 1024.0
    return f"{count:,.1f} PiB"


def _human_duration(seconds: float) -> str:
    seconds = int(seconds)
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours}h{minutes:02d}m{secs:02d}s"
    if minutes:
        return f"{minutes}m{secs:02d}s"
    return f"{secs}s"
