"""
Self-Granted or Dormant Identity Added to High-Risk Group
Trigger: EventBridge rule matching AddUserToGroup.
Use for: Real-time triage of self-granted or suspicious entitlement additions.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "iam.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "AddUserToGroup":
        return {"matched": False}

    return {
        "matched": "requires-self-grant-and-target-identity-context",
        "alert": {
            "rule_id": "det-058",
            "title": "Self-Granted or Dormant Identity Added to High-Risk Group",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "group_name": detail.get("requestParameters", {}).get("groupName"),
            "target_user": detail.get("requestParameters", {}).get("userName"),
            "event_time": detail.get("eventTime"),
        },
    }
