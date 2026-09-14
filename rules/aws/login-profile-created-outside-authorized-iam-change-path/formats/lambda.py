"""
Login Profile Created Outside Authorized IAM Change Path
Trigger: EventBridge rule matching CreateLoginProfile.
Use for: Real-time triage of unauthorized console-password creation.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "iam.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "CreateLoginProfile":
        return {"matched": False}

    return {
        "matched": "requires-authorized-login-profile-manager-check",
        "alert": {
            "rule_id": "det-049",
            "title": "Login Profile Created Outside Authorized IAM Change Path",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "target_user": detail.get("requestParameters", {}).get("userName"),
            "event_time": detail.get("eventTime"),
        },
    }
