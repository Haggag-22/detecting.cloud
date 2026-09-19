"""
UpdateLoginProfile Followed by Console Login
Trigger: EventBridge rule matching UpdateLoginProfile.
Use for: Correlation of password reset with later successful console use.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "iam.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "UpdateLoginProfile":
        return {"matched": False}

    return {
        "matched": "requires-correlation-with-successful-consolelogin",
        "alert": {
            "rule_id": "det-055",
            "title": "UpdateLoginProfile Followed by Console Login",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "target_user": detail.get("requestParameters", {}).get("userName"),
            "event_time": detail.get("eventTime"),
        },
    }
