"""Trail name → S3 resolution."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from collector.errors import ConfigError
from collector.trail_discovery import resolve_trail_s3_source


def test_resolve_trail_s3_source_from_describe_trails():
    session = MagicMock()
    client = MagicMock()
    session.client.return_value = client
    session.region_name = "us-west-2"
    client.describe_trails.return_value = {
        "trailList": [
            {
                "Name": "management-trail",
                "S3BucketName": "company-cloudtrail-logs",
                "S3KeyPrefix": "prod-audit",
                "HomeRegion": "us-east-1",
                "IsMultiRegionTrail": True,
                "IsOrganizationTrail": False,
                "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/management-trail",
            }
        ]
    }

    source = resolve_trail_s3_source(session, "management-trail")

    assert source.bucket == "company-cloudtrail-logs"
    assert source.prefix == "prod-audit/"
    assert source.home_region == "us-east-1"
    assert source.is_multiregion is True
    session.client.assert_called()
    assert session.client.call_args[0][0] == "cloudtrail"
    assert session.client.call_args[1]["region_name"] == "us-west-2"


def test_resolve_trail_not_found():
    session = MagicMock()
    client = MagicMock()
    session.client.return_value = client
    session.region_name = "eu-west-1"
    client.describe_trails.return_value = {"trailList": []}

    with patch("collector.trail_discovery.resolve_regions", return_value=[]):
        with pytest.raises(ConfigError, match="no CloudTrail trail"):
            resolve_trail_s3_source(session, "missing-trail", home_region="eu-west-1")
