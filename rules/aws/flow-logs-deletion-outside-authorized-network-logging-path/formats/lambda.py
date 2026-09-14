"""
Flow Logs Deletion Outside Authorized Network Logging Path
Trigger: EventBridge rule matching DeleteFlowLogs.
Use for: Real-time authorization checks on network telemetry deletion.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ec2.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "DeleteFlowLogs":
        return {"matched": False}

    return {
        "matched": "requires-authorized-flow-log-manager-check",
        "alert": {
            "rule_id": "det-111",
            "title": "Flow Logs Deletion Outside Authorized Network Logging Path",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "flow_log_ids": detail.get("requestParameters", {}).get("flowLogIds"),
            "event_time": detail.get("eventTime"),
        },
    }
