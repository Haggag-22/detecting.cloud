"""
Potential S3 Exfiltration via Anomalous GetObject Burst
Trigger: Streamed CloudTrail S3 data events into a stateful analytics pipeline.
Use for: Sliding-window GetObject burst detection with actor and bucket baselines.
"""

WINDOW_MIN_DOWNLOADS = 25
WINDOW_MIN_DISTINCT_OBJECTS = 25

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "s3.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "GetObject":
        return {"matched": False}

    return {
        "matched": "stateful-evaluation-required",
        "key": {
            "actor": detail.get("userIdentity", {}).get("arn"),
            "bucket": detail.get("requestParameters", {}).get("bucketName"),
            "object_key": detail.get("requestParameters", {}).get("key"),
            "source_ip": detail.get("sourceIPAddress"),
        },
        "thresholds": {
            "min_downloads": WINDOW_MIN_DOWNLOADS,
            "min_distinct_objects": WINDOW_MIN_DISTINCT_OBJECTS,
        },
    }
