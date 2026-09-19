"""
StartSession Outside Authorized Interactive Access Path
Trigger: EventBridge rule matching StartSession.
Use for: Real-time triage of unauthorized interactive Session Manager access.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ssm.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "StartSession":
        return {"matched": False}

    return {
        "matched": "requires-authorized-session-actor-check",
        "alert": {
            "rule_id": "det-076",
            "title": "StartSession Outside Authorized Interactive Access Path",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "target": detail.get("requestParameters", {}).get("target"),
            "event_time": detail.get("eventTime"),
        },
    }
