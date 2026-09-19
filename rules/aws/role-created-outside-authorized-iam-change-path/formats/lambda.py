"""
Role Created Outside Authorized IAM Change Path
Trigger: EventBridge rule matching CreateRole.
Use for: Real-time triage of unauthorized role creation.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "iam.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "CreateRole":
        return {"matched": False}

    return {
        "matched": "requires-authorized-role-creator-check",
        "alert": {
            "rule_id": "det-063",
            "title": "Role Created Outside Authorized IAM Change Path",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "role_name": detail.get("requestParameters", {}).get("roleName"),
            "event_time": detail.get("eventTime"),
        },
    }
