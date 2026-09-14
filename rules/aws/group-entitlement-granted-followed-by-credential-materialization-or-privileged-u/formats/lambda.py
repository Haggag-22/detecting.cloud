"""
Group Entitlement Granted Followed by Credential Materialization or Privileged Use
Trigger: EventBridge rule matching AddUserToGroup.
Use for: Correlation of entitlement grants with later credential creation, console use, or privileged activity.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "iam.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "AddUserToGroup":
        return {"matched": False}

    return {
        "matched": "requires-target-user-correlation-with-follow-on-activity",
        "alert": {
            "rule_id": "det-059",
            "title": "Group Entitlement Granted Followed by Credential Materialization or Privileged Use",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "target_user": detail.get("requestParameters", {}).get("userName"),
            "group_name": detail.get("requestParameters", {}).get("groupName"),
            "event_time": detail.get("eventTime"),
        },
    }
