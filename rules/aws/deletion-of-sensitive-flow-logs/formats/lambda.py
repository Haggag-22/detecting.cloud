"""
Deletion of Sensitive Flow Logs
Trigger: EventBridge rule matching DeleteFlowLogs.
Use for: Real-time sensitive-target classification on network telemetry removal.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ec2.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "DeleteFlowLogs":
        return {"matched": False}

    return {
        "matched": "requires-sensitive-flow-log-target-check",
        "alert": {
            "rule_id": "det-112",
            "title": "Deletion of Sensitive Flow Logs",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "flow_log_ids": detail.get("requestParameters", {}).get("flowLogIds"),
            "event_time": detail.get("eventTime"),
        },
    }
