"""
IAM User Added to Group
Trigger: EventBridge rule matching AddUserToGroup.
Use for: Baseline visibility into IAM entitlement changes.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "iam.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "AddUserToGroup":
        return {"matched": False}

    request = detail.get("requestParameters", {})
    return {
        "matched": True,
        "alert": {
            "rule_id": "det-056",
            "title": "IAM User Added to Group",
            "severity": "Medium",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "target_user": request.get("userName"),
            "group_name": request.get("groupName"),
            "event_time": detail.get("eventTime"),
            "source_ip": detail.get("sourceIPAddress"),
        },
    }
