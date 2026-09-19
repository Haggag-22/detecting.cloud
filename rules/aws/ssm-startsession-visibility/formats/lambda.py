"""
SSM StartSession Visibility
Trigger: EventBridge rule matching StartSession.
Use for: Baseline visibility into interactive Session Manager access.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ssm.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "StartSession":
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-075",
            "title": "SSM StartSession Visibility",
            "severity": "Medium",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "target": detail.get("requestParameters", {}).get("target"),
            "event_time": detail.get("eventTime"),
            "source_ip": detail.get("sourceIPAddress"),
        },
    }
