"""
Secrets Manager Bulk Secret Retrieval
Trigger: EventBridge rule matching GetSecretValue.
Use for: Real-time aggregation of unusual breadth of secret access.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "secretsmanager.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "GetSecretValue":
        return {"matched": False}

    return {
        "matched": "requires-stateful-distinct-secret-counting",
        "alert": {
            "rule_id": "det-028",
            "title": "Secrets Manager Bulk Secret Retrieval",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "secret_id": detail.get("requestParameters", {}).get("secretId"),
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
