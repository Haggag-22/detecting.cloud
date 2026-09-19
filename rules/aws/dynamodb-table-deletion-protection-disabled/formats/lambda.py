"""
DynamoDB Table Deletion Protection Disabled
Trigger: EventBridge rule matching UpdateTable.
Use for: Real-time alerting on removal of DynamoDB deletion protection.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "dynamodb.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "UpdateTable":
        return {"matched": False}
    if detail.get("requestParameters", {}).get("deletionProtectionEnabled") is not False:
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-024",
            "title": "DynamoDB Table Deletion Protection Disabled",
            "severity": "Medium",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "table_name": detail.get("requestParameters", {}).get("tableName"),
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
