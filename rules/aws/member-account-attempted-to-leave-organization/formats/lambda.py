"""
Member Account Attempted to Leave Organization
Trigger: EventBridge rule matching LeaveOrganization.
Use for: Baseline visibility into organization-escape attempts.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "organizations.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "LeaveOrganization":
        return {"matched": False}

    user_identity = detail.get("userIdentity", {})
    return {
        "matched": True,
        "alert": {
            "rule_id": "det-114",
            "title": "Member Account Attempted to Leave Organization",
            "severity": "Critical",
            "actor": user_identity.get("arn") or user_identity.get("accountId"),
            "account_id": detail.get("recipientAccountId"),
            "event_time": detail.get("eventTime"),
        },
    }
