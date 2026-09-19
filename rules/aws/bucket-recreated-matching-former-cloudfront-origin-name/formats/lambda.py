"""
Bucket Recreated Matching Former CloudFront Origin Name
Trigger: EventBridge rule matching CreateBucket.
Use for: Detecting reuse of bucket names tied to orphaned CloudFront origins.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "s3.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "CreateBucket":
        return {"matched": False}

    return {
        "matched": "requires-orphaned-origin-bucket-name-baseline-check",
        "alert": {
            "rule_id": "det-139",
            "title": "Bucket Recreated Matching Former CloudFront Origin Name",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "bucket_name": detail.get("requestParameters", {}).get("bucketName"),
            "event_time": detail.get("eventTime"),
        },
    }
