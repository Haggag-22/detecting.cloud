"""
Failed LeaveOrganization Attempt
Trigger: EventBridge rule matching LeaveOrganization.
Use for: Real-time detection of blocked organization-escape attempts.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "organizations.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "LeaveOrganization":
        return {"matched": False}
    if not detail.get("errorCode"):
        return {"matched": False}

    user_identity = detail.get("userIdentity", {})
    return {
        "matched": True,
        "alert": {
            "rule_id": "det-116",
            "title": "Failed LeaveOrganization Attempt",
            "severity": "Critical",
            "actor": user_identity.get("arn") or user_identity.get("accountId"),
            "error_code": detail.get("errorCode"),
            "account_id": detail.get("recipientAccountId"),
            "event_time": detail.get("eventTime"),
        },
    }
