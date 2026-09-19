"""
S3 ACL Changed
Trigger: EventBridge rule matching PutBucketAcl or PutObjectAcl.
Use for: Baseline visibility into S3 ACL mutations.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "s3.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in {"PutBucketAcl", "PutObjectAcl"}:
        return {"matched": False}

    request = detail.get("requestParameters", {})
    return {
        "matched": True,
        "alert": {
            "rule_id": "det-131",
            "title": "S3 ACL Changed",
            "severity": "Medium",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "bucket_name": request.get("bucketName"),
            "object_key": request.get("key"),
            "event_time": detail.get("eventTime"),
        },
    }
