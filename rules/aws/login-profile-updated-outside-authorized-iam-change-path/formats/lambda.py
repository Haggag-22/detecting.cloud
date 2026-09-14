"""
Login Profile Updated Outside Authorized IAM Change Path
Trigger: EventBridge rule matching UpdateLoginProfile.
Use for: Real-time triage of unauthorized password reset activity.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "iam.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "UpdateLoginProfile":
        return {"matched": False}

    return {
        "matched": "requires-authorized-password-reset-actor-check",
        "alert": {
            "rule_id": "det-053",
            "title": "Login Profile Updated Outside Authorized IAM Change Path",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "target_user": detail.get("requestParameters", {}).get("userName"),
            "event_time": detail.get("eventTime"),
        },
    }
