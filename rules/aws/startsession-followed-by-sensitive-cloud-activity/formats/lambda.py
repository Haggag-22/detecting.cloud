"""
StartSession Followed by Sensitive Cloud Activity
Trigger: EventBridge rule matching StartSession.
Use for: Correlation from interactive access to later sensitive API use.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ssm.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "StartSession":
        return {"matched": False}

    return {
        "matched": "requires-startsession-plus-sensitive-activity-correlation",
        "alert": {
            "rule_id": "det-078",
            "title": "StartSession Followed by Sensitive Cloud Activity",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "target": detail.get("requestParameters", {}).get("target"),
            "event_time": detail.get("eventTime"),
        },
    }
