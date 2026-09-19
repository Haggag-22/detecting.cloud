"""
Flow Logs Removal Followed by Suspicious Network or Exfiltration Behavior
Trigger: EventBridge rule matching DeleteFlowLogs.
Use for: Correlation from telemetry removal to later suspicious cloud activity.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ec2.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "DeleteFlowLogs":
        return {"matched": False}

    return {
        "matched": "requires-flow-log-deletion-plus-follow-on-activity-correlation",
        "alert": {
            "rule_id": "det-113",
            "title": "Flow Logs Removal Followed by Suspicious Network or Exfiltration Behavior",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "flow_log_ids": detail.get("requestParameters", {}).get("flowLogIds"),
            "event_time": detail.get("eventTime"),
        },
    }
