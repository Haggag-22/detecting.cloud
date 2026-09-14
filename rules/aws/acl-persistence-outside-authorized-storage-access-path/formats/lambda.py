"""
ACL Persistence Outside Authorized Storage Access Path
Trigger: EventBridge rule matching PutBucketAcl or PutObjectAcl.
Use for: Authorization checks on S3 ACL mutations.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "s3.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in {"PutBucketAcl", "PutObjectAcl"}:
        return {"matched": False}

    return {
        "matched": "requires-authorized-s3-acl-actor-check",
        "alert": {
            "rule_id": "det-134",
            "title": "ACL Persistence Outside Authorized Storage Access Path",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "bucket_name": detail.get("requestParameters", {}).get("bucketName"),
            "event_time": detail.get("eventTime"),
        },
    }
