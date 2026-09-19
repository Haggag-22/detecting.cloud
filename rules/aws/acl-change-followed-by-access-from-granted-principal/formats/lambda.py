"""
ACL Change Followed by Access from Granted Principal
Trigger: EventBridge rule matching PutBucketAcl or PutObjectAcl.
Use for: Correlation from ACL grant to later S3 access by the grantee.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "s3.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in {"PutBucketAcl", "PutObjectAcl"}:
        return {"matched": False}

    return {
        "matched": "requires-acl-grantee-plus-s3-access-correlation",
        "alert": {
            "rule_id": "det-135",
            "title": "ACL Change Followed by Access from Granted Principal",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "bucket_name": detail.get("requestParameters", {}).get("bucketName"),
            "event_time": detail.get("eventTime"),
        },
    }
