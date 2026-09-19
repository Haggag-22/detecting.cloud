"""
CreateLoginProfile Followed by Console Login
Trigger: EventBridge rule matching CreateLoginProfile.
Use for: Correlation with later successful console authentication by the same target user.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "iam.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "CreateLoginProfile":
        return {"matched": False}

    return {
        "matched": "requires-correlation-with-successful-consolelogin",
        "alert": {
            "rule_id": "det-051",
            "title": "CreateLoginProfile Followed by Console Login",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "target_user": detail.get("requestParameters", {}).get("userName"),
            "event_time": detail.get("eventTime"),
        },
    }
