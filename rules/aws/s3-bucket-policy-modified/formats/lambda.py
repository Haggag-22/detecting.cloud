"""
S3 Bucket Policy Modified
Trigger: EventBridge rule matching PutBucketPolicy or DeleteBucketPolicy.
Use for: Real-time policy parsing and exposure analysis.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "s3.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in ("PutBucketPolicy", "DeleteBucketPolicy"):
        return {"matched": False}

    return {
        "matched": "requires-policy-analysis",
        "alert": {
            "rule_id": "det-017",
            "title": "S3 Bucket Policy Modified",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "bucket_name": detail.get("requestParameters", {}).get("bucketName"),
            "event_name": detail.get("eventName"),
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
