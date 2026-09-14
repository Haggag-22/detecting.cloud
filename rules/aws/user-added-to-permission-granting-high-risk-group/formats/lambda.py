"""
User Added to Permission-Granting High-Risk Group
Trigger: EventBridge rule matching AddUserToGroup.
Use for: Real-time enrichment against group effective permissions.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "iam.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "AddUserToGroup":
        return {"matched": False}

    return {
        "matched": "requires-group-permission-resolution",
        "alert": {
            "rule_id": "det-057",
            "title": "User Added to Permission-Granting High-Risk Group",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "group_name": detail.get("requestParameters", {}).get("groupName"),
            "target_user": detail.get("requestParameters", {}).get("userName"),
            "event_time": detail.get("eventTime"),
        },
    }
