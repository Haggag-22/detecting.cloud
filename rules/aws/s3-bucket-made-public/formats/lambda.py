"""
S3 Bucket Made Public
Trigger: EventBridge rule matching DeletePublicAccessBlock or PutPublicAccessBlock.
Use for: Real-time alerting on weakened bucket-level public-access guardrails.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "s3.amazonaws.com":
        return {"matched": False}

    event_name = detail.get("eventName")
    if event_name == "DeletePublicAccessBlock":
        return {
            "matched": True,
            "alert": {
                "rule_id": "det-018",
                "title": "S3 Bucket Made Public",
                "severity": "Critical",
                "actor": detail.get("userIdentity", {}).get("arn"),
                "bucket_name": detail.get("requestParameters", {}).get("bucketName"),
                "source_ip": detail.get("sourceIPAddress"),
                "event_time": detail.get("eventTime"),
            },
        }

    if event_name == "PutPublicAccessBlock":
        config = detail.get("requestParameters", {}).get("PublicAccessBlockConfiguration", {})
        weakened = config.get("BlockPublicPolicy") is False or config.get("RestrictPublicBuckets") is False or config.get("BlockPublicAcls") is False or config.get("IgnorePublicAcls") is False
        if weakened:
            return {
                "matched": True,
                "alert": {
                    "rule_id": "det-018",
                    "title": "S3 Bucket Made Public",
                    "severity": "Critical",
                    "actor": detail.get("userIdentity", {}).get("arn"),
                    "bucket_name": detail.get("requestParameters", {}).get("bucketName"),
                    "source_ip": detail.get("sourceIPAddress"),
                    "event_time": detail.get("eventTime"),
                },
            }

    return {"matched": False}
