"""
Login Profile Updated for Sensitive or Console-Ineligible User
Trigger: EventBridge rule matching UpdateLoginProfile.
Use for: Real-time triage of password resets on high-risk or unexpected target users.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "iam.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "UpdateLoginProfile":
        return {"matched": False}

    return {
        "matched": "requires-target-user-classification",
        "alert": {
            "rule_id": "det-054",
            "title": "Login Profile Updated for Sensitive or Console-Ineligible User",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "target_user": detail.get("requestParameters", {}).get("userName"),
            "event_time": detail.get("eventTime"),
        },
    }
