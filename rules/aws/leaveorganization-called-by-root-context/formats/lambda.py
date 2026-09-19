"""
LeaveOrganization Called by Root Context
Trigger: EventBridge rule matching LeaveOrganization.
Use for: Real-time detection of root-initiated organization escape.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "organizations.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "LeaveOrganization":
        return {"matched": False}
    if detail.get("userIdentity", {}).get("type") != "Root":
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-115",
            "title": "LeaveOrganization Called by Root Context",
            "severity": "Critical",
            "account_id": detail.get("recipientAccountId"),
            "event_time": detail.get("eventTime"),
        },
    }
