"""
IAM Policy Removal With Potential Permission Expansion
Trigger: EventBridge rule matching Detach*Policy or Delete*Policy.
Use for: Baseline visibility plus enrichment for harmful removal scenarios.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "iam.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in ("DetachUserPolicy", "DetachRolePolicy", "DeleteUserPolicy", "DeleteRolePolicy"):
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-038",
            "title": "IAM Policy Removal With Potential Permission Expansion",
            "severity": "Medium",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "event_name": detail.get("eventName"),
            "policy_arn": detail.get("requestParameters", {}).get("policyArn"),
            "policy_name": detail.get("requestParameters", {}).get("policyName"),
            "target_role": detail.get("requestParameters", {}).get("roleName"),
            "target_user": detail.get("requestParameters", {}).get("userName"),
            "event_time": detail.get("eventTime"),
        },
    }
