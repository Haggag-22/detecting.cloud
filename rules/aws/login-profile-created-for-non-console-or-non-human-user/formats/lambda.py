"""
Login Profile Created for Non-Console or Non-Human User
Trigger: EventBridge rule matching CreateLoginProfile.
Use for: Real-time triage of console passwords created for ineligible user classes.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "iam.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "CreateLoginProfile":
        return {"matched": False}

    return {
        "matched": "requires-user-eligibility-and-console-history-check",
        "alert": {
            "rule_id": "det-050",
            "title": "Login Profile Created for Non-Console or Non-Human User",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "target_user": detail.get("requestParameters", {}).get("userName"),
            "event_time": detail.get("eventTime"),
        },
    }
