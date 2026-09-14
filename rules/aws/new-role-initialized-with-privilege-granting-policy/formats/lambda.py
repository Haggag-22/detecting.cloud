"""
New Role Initialized with Privilege-Granting Policy
Trigger: EventBridge rule matching CreateRole, AttachRolePolicy, or PutRolePolicy.
Use for: Correlation of role creation with immediate high-risk permission grants.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "iam.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in {"CreateRole", "AttachRolePolicy", "PutRolePolicy"}:
        return {"matched": False}

    return {
        "matched": "requires-role-creation-plus-policy-correlation",
        "alert": {
            "rule_id": "det-062",
            "title": "New Role Initialized with Privilege-Granting Policy",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "role_name": detail.get("requestParameters", {}).get("roleName"),
            "event_name": detail.get("eventName"),
            "event_time": detail.get("eventTime"),
        },
    }
