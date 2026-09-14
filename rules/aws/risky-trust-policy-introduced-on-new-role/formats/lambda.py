"""
Risky Trust Policy Introduced on New Role
Trigger: EventBridge rule matching CreateRole.
Use for: Real-time trust-policy parsing on newly created roles.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "iam.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "CreateRole":
        return {"matched": False}

    return {
        "matched": "requires-trust-policy-semantic-analysis",
        "alert": {
            "rule_id": "det-061",
            "title": "Risky Trust Policy Introduced on New Role",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "role_name": detail.get("requestParameters", {}).get("roleName"),
            "event_time": detail.get("eventTime"),
        },
    }
