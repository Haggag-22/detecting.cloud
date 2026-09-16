"""Chain-of-custody manifest.

The manifest is the document that answers, later and under challenge, "what
exactly did you collect, from where, and how do you know it wasn't altered?"

Two properties matter more than completeness:

* It must record failures as prominently as successes. A manifest that lists
  40,000 objects and omits the 12 that failed is worse than no manifest.
* It must never claim a hash it did not compute. Mode A copies are server-side,
  so the bytes never reach this host and a locally-computed SHA256 is not
  possible without egressing the entire dataset. S3 computes the checksum
  instead, and the manifest says so explicitly, including whether the value is
  a whole-object or a multipart composite digest.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, BinaryIO, Literal

from . import COLLECTOR_NAME, __version__

# How a recorded digest was produced. Stored per object so nobody has to infer
# it from the run mode later.
DigestMethod = Literal[
    "s3-sha256",            # whole-object SHA256, computed by S3 on CopyObject
    "s3-sha256-composite",  # multipart composite ("<hex>-<parts>"), NOT a whole-object hash
    "local-sha256",         # computed here while streaming the bytes we generated
    "none",                 # no digest available; reason recorded alongside
]


@dataclass(slots=True)
class CollectedObject:
    """One object successfully written into the evidence set."""

    source_key: str
    dest_key: str
    size_bytes: int
    digest: str | None
    digest_method: DigestMethod
    source_etag: str | None = None
    dest_etag: str | None = None
    event_count: int | None = None
    digest_note: str | None = None


@dataclass(slots=True)
class FailedObject:
    """An object that could not be collected. Never silently dropped."""

    source_key: str
    dest_key: str | None
    error: str
    attempts: int


@dataclass(slots=True)
class FailedWindow:
    """A Mode B time window that could not be pulled to completion."""

    region: str
    window_start: str
    window_end: str
    error: str
    events_written_before_failure: int


@dataclass(slots=True)
class ManifestBuilder:
    """Accumulates the record of one collection run.

    Thread-safe: Mode A copies objects from a thread pool, and a lost manifest
    entry would mean an object present in the bucket but absent from the record
    of custody.
    """

    run_id: str
    mode: str
    engagement_id: str
    dest_bucket: str
    dest_prefix: str
    requested_start: str | None = None
    requested_end: str | None = None
    source_bucket: str | None = None
    source_account_id: str | None = None
    regions: list[str] = field(default_factory=list)
    in_place: bool = False
    dry_run: bool = False
    notes: list[str] = field(default_factory=list)

    started_at: str = field(default_factory=lambda: _now_iso())
    _objects: list[CollectedObject] = field(default_factory=list, repr=False)
    _failed_objects: list[FailedObject] = field(default_factory=list, repr=False)
    _failed_windows: list[FailedWindow] = field(default_factory=list, repr=False)
    _event_count: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def add_object(self, obj: CollectedObject) -> None:
        with self._lock:
            self._objects.append(obj)
            if obj.event_count:
                self._event_count += obj.event_count

    def add_failed_object(self, failure: FailedObject) -> None:
        with self._lock:
            self._failed_objects.append(failure)

    def add_failed_window(self, failure: FailedWindow) -> None:
        with self._lock:
            self._failed_windows.append(failure)

    def add_note(self, note: str) -> None:
        with self._lock:
            self.notes.append(note)

    @property
    def object_count(self) -> int:
        with self._lock:
            return len(self._objects)

    @property
    def failure_count(self) -> int:
        with self._lock:
            return len(self._failed_objects) + len(self._failed_windows)

    @property
    def total_bytes(self) -> int:
        with self._lock:
            return sum(o.size_bytes for o in self._objects)

    def build(self) -> dict[str, Any]:
        """Render the manifest document."""
        with self._lock:
            complete = not self._failed_objects and not self._failed_windows
            return {
                "manifest_version": 1,
                "collector": {
                    "name": COLLECTOR_NAME,
                    "version": __version__,
                },
                "run": {
                    "run_id": self.run_id,
                    "mode": self.mode,
                    "engagement_id": self.engagement_id,
                    "started_at": self.started_at,
                    "completed_at": _now_iso(),
                    "in_place": self.in_place,
                    "dry_run": self.dry_run,
                    # The single most important field for an analyst reading this
                    # later: it says whether a gap in the data is real.
                    "collection_complete": complete,
                },
                "source": {
                    "bucket": self.source_bucket,
                    "account_id": self.source_account_id,
                    "regions": sorted(self.regions),
                    "requested_start": self.requested_start,
                    "requested_end": self.requested_end,
                },
                "destination": {
                    "bucket": self.dest_bucket,
                    "prefix": self.dest_prefix,
                },
                "totals": {
                    "objects_collected": len(self._objects),
                    "bytes_collected": sum(o.size_bytes for o in self._objects),
                    "events_collected": self._event_count,
                    "objects_failed": len(self._failed_objects),
                    "windows_failed": len(self._failed_windows),
                },
                "fidelity": _fidelity_statement(self.mode),
                "notes": list(self.notes),
                "objects": [asdict(o) for o in self._objects],
                "failed_objects": [asdict(f) for f in self._failed_objects],
                "failed_windows": [asdict(f) for f in self._failed_windows],
            }

    def to_json(self) -> bytes:
        return json.dumps(self.build(), indent=2, sort_keys=False).encode("utf-8")


def _fidelity_statement(mode: str) -> dict[str, Any]:
    """What this mode can and cannot have captured.

    Recorded in the manifest so an analyst who finds no data events knows
    whether that means "none occurred" or "this mode cannot see them".
    """
    if mode == "lookup":
        return {
            "mode": "lookup",
            "management_events": True,
            "data_events": False,
            "insights_events": False,
            "max_history_days": 90,
            "statement": (
                "Collected via the CloudTrail LookupEvents API. Management events "
                "ONLY. Data events (S3 object-level, Lambda invoke, DynamoDB item "
                "operations) and Insights events are NOT returned by this API and "
                "are therefore absent from this evidence set as a collection "
                "artifact, not as evidence that none occurred. History is limited "
                "to 90 days."
            ),
            "ingest_format": (
                'Gzip JSON objects {"Records":[...]} matching native CloudTrail S3 '
                "logs for the sof-elk-docker Logstash pipeline (cloudtrail index)."
            ),
        }
    return {
        "mode": "trail",
        "management_events": True,
        "data_events": "as configured on the source trail",
        "insights_events": "as configured on the source trail",
        "max_history_days": None,
        "statement": (
            "Collected by server-side copy from a CloudTrail trail's S3 bucket. "
            "Fidelity equals the source trail's configuration: data events and "
            "Insights events are present if and only if the trail was configured "
            "to record them."
        ),
        "ingest_format": (
            "Unmodified CloudTrail S3 gzip JSON (native Records layout) for "
            "sof-elk-docker Logstash → cloudtrail index."
        ),
    }


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_stream(stream: BinaryIO, chunk_size: int = 1024 * 1024) -> str:
    """Hex SHA256 of a stream, read in bounded chunks.

    Used for locally-generated bytes only. Never used to hash a copied object,
    because doing so would require downloading the entire evidence set.
    """
    digest = hashlib.sha256()
    while chunk := stream.read(chunk_size):
        digest.update(chunk)
    return digest.hexdigest()


def s3_checksum_to_hex(checksum: str) -> tuple[str, DigestMethod]:
    """Convert an S3 ``ChecksumSHA256`` header value to hex.

    S3 returns base64. For multipart objects it returns a *composite* digest
    suffixed ``-<partcount>``: the SHA256 of the concatenated part digests, not
    the SHA256 of the object's bytes. Those two things are not interchangeable
    and conflating them in an evidence manifest would be a false claim, so the
    method is returned alongside the value.
    """
    if not checksum:
        raise ValueError("empty checksum")

    if "-" in checksum:
        encoded, _, parts = checksum.rpartition("-")
        return f"{_b64_to_hex(encoded)}-{parts}", "s3-sha256-composite"
    return _b64_to_hex(checksum), "s3-sha256"


def _b64_to_hex(encoded: str) -> str:
    try:
        return base64.b64decode(encoded, validate=True).hex()
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"checksum {encoded!r} is not valid base64: {exc}") from exc


COMPOSITE_DIGEST_NOTE = (
    "Multipart composite digest: SHA256 of the concatenated part digests, not a "
    "whole-object SHA256. Verify by recomputing with the same part size."
)

NO_DIGEST_NOTE = (
    "No SHA256 available. The source object carried no checksum and hashing it "
    "here would require egressing the object, which this tool does not do."
)
