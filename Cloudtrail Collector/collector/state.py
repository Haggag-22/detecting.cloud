"""Resumable run state.

Design constraints:

* A run can be killed at any instant (SIGKILL, host reboot, expired SSO).
  Whatever reached disk must still be valid, so the format is append-only
  NDJSON: a torn final line is detected and discarded, never misread.
* The state file is scoped to one engagement + mode + source. Resuming a run
  against a *different* source would produce an evidence set whose manifest
  does not describe its contents, so the header is checked and a mismatch is a
  hard failure rather than a warning.
* Mode A records completed destination keys; Mode B records per-window
  checkpoints.
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import StateError

HEADER_KIND = "header"
COMPLETED_KIND = "completed"
CHECKPOINT_KIND = "checkpoint"
WINDOW_DONE_KIND = "window_done"


@dataclass(slots=True)
class Checkpoint:
    """Mode B progress inside one window."""

    region: str
    window_start: str
    window_end: str
    last_token: str | None
    events_written: int


class RunState:
    """Append-only state file with an fsync'd write path."""

    def __init__(self, path: Path, identity: dict[str, Any]) -> None:
        self._path = path
        self._identity = identity
        self._lock = threading.Lock()
        self._handle = None
        self._completed: set[str] = set()
        self._checkpoints: dict[str, Checkpoint] = {}
        self._finished_windows: set[str] = set()

    @property
    def path(self) -> Path:
        return self._path

    @property
    def completed_keys(self) -> set[str]:
        return self._completed

    def load(self, *, resume: bool) -> None:
        """Read existing state, or start fresh.

        When ``resume`` is False and a state file exists, we refuse rather than
        overwrite: the existing file may be the only record of a partially
        completed collection.
        """
        if not self._path.exists():
            self._open(truncate=True)
            self._write({"kind": HEADER_KIND, **self._identity})
            return

        if not resume:
            raise StateError(
                f"state file {self._path} already exists. Pass --resume to continue "
                f"that run, or --state-file to start a separate one. Refusing to "
                f"overwrite: it may be the only record of a partial collection."
            )

        self._replay()
        self._open(truncate=False)

    def _replay(self) -> None:
        header_seen = False
        with self._path.open("r", encoding="utf-8") as handle:
            for lineno, line in enumerate(handle, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    # Only the final line may be torn — anything earlier means
                    # the file was corrupted by something other than a crash.
                    remainder = handle.read().strip()
                    if remainder:
                        raise StateError(
                            f"{self._path}:{lineno} is corrupt and is not the final "
                            f"line. Refusing to resume from an unreliable state file."
                        ) from None
                    break

                kind = record.get("kind")
                if kind == HEADER_KIND:
                    self._check_identity(record)
                    header_seen = True
                elif kind == COMPLETED_KIND:
                    self._completed.add(record["dest_key"])
                elif kind == CHECKPOINT_KIND:
                    checkpoint = Checkpoint(
                        region=record["region"],
                        window_start=record["window_start"],
                        window_end=record["window_end"],
                        last_token=record.get("last_token"),
                        events_written=record.get("events_written", 0),
                    )
                    self._checkpoints[_window_key(checkpoint.region, checkpoint.window_start, checkpoint.window_end)] = checkpoint
                elif kind == WINDOW_DONE_KIND:
                    self._finished_windows.add(
                        _window_key(record["region"], record["window_start"], record["window_end"])
                    )

        if not header_seen:
            raise StateError(
                f"{self._path} has no header record; it was not written by this tool"
            )

    def _check_identity(self, header: dict[str, Any]) -> None:
        for field_name, expected in self._identity.items():
            actual = header.get(field_name)
            if actual != expected:
                raise StateError(
                    f"state file {self._path} belongs to a different run: "
                    f"{field_name} is {actual!r} on disk but {expected!r} for this "
                    f"invocation. Resuming would produce an evidence set whose "
                    f"manifest does not describe its contents."
                )

    def _open(self, *, truncate: bool) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = self._path.open("w" if truncate else "a", encoding="utf-8")

    def _write(self, record: dict[str, Any]) -> None:
        if self._handle is None:
            raise StateError("state file is not open; call load() first")
        with self._lock:
            self._handle.write(json.dumps(record, separators=(",", ":")) + "\n")
            self._handle.flush()
            os.fsync(self._handle.fileno())

    def mark_completed(self, dest_key: str) -> None:
        self._completed.add(dest_key)
        self._write({"kind": COMPLETED_KIND, "dest_key": dest_key})

    def is_completed(self, dest_key: str) -> bool:
        return dest_key in self._completed

    def save_checkpoint(self, checkpoint: Checkpoint) -> None:
        key = _window_key(checkpoint.region, checkpoint.window_start, checkpoint.window_end)
        self._checkpoints[key] = checkpoint
        self._write(
            {
                "kind": CHECKPOINT_KIND,
                "region": checkpoint.region,
                "window_start": checkpoint.window_start,
                "window_end": checkpoint.window_end,
                "last_token": checkpoint.last_token,
                "events_written": checkpoint.events_written,
            }
        )

    def mark_window_done(self, region: str, window_start: str, window_end: str) -> None:
        self._finished_windows.add(_window_key(region, window_start, window_end))
        self._write(
            {
                "kind": WINDOW_DONE_KIND,
                "region": region,
                "window_start": window_start,
                "window_end": window_end,
            }
        )

    def is_window_done(self, region: str, window_start: str, window_end: str) -> bool:
        return _window_key(region, window_start, window_end) in self._finished_windows

    def checkpoint_for(self, region: str, window_start: str, window_end: str) -> Checkpoint | None:
        return self._checkpoints.get(_window_key(region, window_start, window_end))

    def close(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None

    def __enter__(self) -> "RunState":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


def _window_key(region: str, start: str, end: str) -> str:
    return f"{region}|{start}|{end}"
