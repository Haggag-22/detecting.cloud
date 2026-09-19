"""
SSM Run Command Execution
Trigger: EventBridge rule matching SendCommand or StartSession.
Use for: Real-time alerting on remote execution and interactive shell access via SSM.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ssm.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in ("SendCommand", "StartSession"):
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-029",
            "title": "SSM Run Command Execution",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "event_name": detail.get("eventName"),
            "document_name": detail.get("requestParameters", {}).get("documentName"),
            "instance_ids": detail.get("requestParameters", {}).get("instanceIds"),
            "target": detail.get("requestParameters", {}).get("target"),
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
