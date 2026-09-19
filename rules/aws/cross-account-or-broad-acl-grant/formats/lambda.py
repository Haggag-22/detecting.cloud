"""
Cross-Account or Broad ACL Grant
Trigger: EventBridge rule matching PutBucketAcl or PutObjectAcl.
Use for: Real-time detection of risky S3 ACL grants.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "s3.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in {"PutBucketAcl", "PutObjectAcl"}:
        return {"matched": False}

    return {
        "matched": "requires-acl-grant-scope-parsing",
        "alert": {
            "rule_id": "det-133",
            "title": "Cross-Account or Broad ACL Grant",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "bucket_name": detail.get("requestParameters", {}).get("bucketName"),
            "event_time": detail.get("eventTime"),
        },
    }
