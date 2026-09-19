"""
IAM Inline Policy Modification
Trigger: EventBridge rule matching PutRolePolicy or PutUserPolicy.
Use for: Real-time baseline visibility into inline policy changes.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "iam.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in ("PutRolePolicy", "PutUserPolicy"):
        return {"matched": False}

    request = detail.get("requestParameters", {})
    return {
        "matched": True,
        "alert": {
            "rule_id": "det-031",
            "title": "IAM Inline Policy Modification",
            "severity": "Medium",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "target_role": request.get("roleName"),
            "target_user": request.get("userName"),
            "policy_name": request.get("policyName"),
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
