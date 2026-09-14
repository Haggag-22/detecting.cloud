"""
DynamoDB Table Exported to S3
Trigger: EventBridge rule matching ExportTableToPointInTime.
Use for: Real-time triage of sensitive or unapproved table exports.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "dynamodb.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "ExportTableToPointInTime":
        return {"matched": False}

    return {
        "matched": "requires-destination-allowlist-check",
        "alert": {
            "rule_id": "det-023",
            "title": "DynamoDB Table Exported to S3",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "table_arn": detail.get("requestParameters", {}).get("tableArn"),
            "s3_bucket": detail.get("requestParameters", {}).get("s3Bucket"),
            "s3_prefix": detail.get("requestParameters", {}).get("s3Prefix"),
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
