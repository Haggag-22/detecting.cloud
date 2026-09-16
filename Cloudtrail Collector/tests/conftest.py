"""Shared fixtures.

The fake S3 client models only the behaviour the collector depends on, but it
models it strictly: multipart parts must be uploaded before completion, and a
completed object is the exact concatenation of its parts in part-number order.
A sink bug that reorders or drops a part shows up here as corrupted gzip.
"""

from __future__ import annotations

import pytest


class FakeS3:
    """Minimal in-memory stand-in for the S3 multipart API."""

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}
        self.uploads: dict[str, dict] = {}
        self.aborted: list[str] = []
        self.deleted: list[str] = []
        self._counter = 0

    def create_multipart_upload(self, Bucket, Key, **kwargs):
        self._counter += 1
        upload_id = f"upload-{self._counter}"
        self.uploads[upload_id] = {"key": Key, "parts": {}}
        return {"UploadId": upload_id}

    def upload_part(self, Bucket, Key, UploadId, PartNumber, Body):
        if UploadId not in self.uploads:
            raise AssertionError(f"upload_part on unknown upload {UploadId}")
        self.uploads[UploadId]["parts"][PartNumber] = Body
        return {"ETag": f'"etag-{PartNumber}"'}

    def complete_multipart_upload(self, Bucket, Key, UploadId, MultipartUpload):
        upload = self.uploads.pop(UploadId)
        ordered = [upload["parts"][p["PartNumber"]] for p in MultipartUpload["Parts"]]
        self.objects[Key] = b"".join(ordered)
        return {"ETag": '"final-etag"'}

    def abort_multipart_upload(self, Bucket, Key, UploadId):
        self.aborted.append(Key)
        self.uploads.pop(UploadId, None)

    def put_object(self, Bucket, Key, Body, **kwargs):
        self.objects[Key] = Body
        return {"ETag": '"put-etag"'}

    @property
    def in_flight_parts(self) -> int:
        return sum(len(u["parts"]) for u in self.uploads.values())


@pytest.fixture
def fake_s3() -> FakeS3:
    return FakeS3()
