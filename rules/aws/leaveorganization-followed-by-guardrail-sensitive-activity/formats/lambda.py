"""
LeaveOrganization Followed by Guardrail-Sensitive Activity
Trigger: EventBridge rule matching LeaveOrganization.
Use for: Correlation from organization escape to later guardrail-sensitive activity.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "organizations.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "LeaveOrganization":
        return {"matched": False}

    user_identity = detail.get("userIdentity", {})
    return {
        "matched": "requires-leaveorganization-plus-guardrail-sensitive-correlation",
        "alert": {
            "rule_id": "det-117",
            "title": "LeaveOrganization Followed by Guardrail-Sensitive Activity",
            "severity": "Critical",
            "actor": user_identity.get("arn") or user_identity.get("accountId"),
            "account_id": detail.get("recipientAccountId"),
            "event_time": detail.get("eventTime"),
        },
    }
