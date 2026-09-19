"""
Orphaned Origin Followed by Bucket Reuse and Content Activity
Trigger: EventBridge rule matching CreateBucket or PutObject.
Use for: Correlation from orphaned-origin bucket reuse into content activation.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "s3.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in {"CreateBucket", "PutObject"}:
        return {"matched": False}

    return {
        "matched": "requires-orphaned-origin-reuse-plus-content-correlation",
        "alert": {
            "rule_id": "det-140",
            "title": "Orphaned Origin Followed by Bucket Reuse and Content Activity",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "bucket_name": detail.get("requestParameters", {}).get("bucketName"),
            "event_time": detail.get("eventTime"),
        },
    }
