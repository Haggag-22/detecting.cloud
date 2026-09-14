"""
ACL Changed on ACL-Effective Target
Trigger: EventBridge rule matching PutBucketAcl or PutObjectAcl.
Use for: Evaluating whether S3 ACL mutations are materially effective.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "s3.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in {"PutBucketAcl", "PutObjectAcl"}:
        return {"matched": False}
    if detail.get("errorCode"):
        return {"matched": False}

    return {
        "matched": "requires-acl-effectiveness-check",
        "alert": {
            "rule_id": "det-132",
            "title": "ACL Changed on ACL-Effective Target",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "bucket_name": detail.get("requestParameters", {}).get("bucketName"),
            "event_time": detail.get("eventTime"),
        },
    }
