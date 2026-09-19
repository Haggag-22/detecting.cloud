"""
Policy Removal Outside Authorized IAM Change Path
Trigger: EventBridge rule matching Detach*Policy or Delete*Policy.
Use for: Real-time triage of IAM removals requiring authorization-context enrichment.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "iam.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in ("DetachUserPolicy", "DetachRolePolicy", "DeleteUserPolicy", "DeleteRolePolicy"):
        return {"matched": False}

    return {
        "matched": "requires-authorized-iam-removal-actor-check",
        "alert": {
            "rule_id": "det-040",
            "title": "Policy Removal Outside Authorized IAM Change Path",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "event_name": detail.get("eventName"),
            "policy_arn": detail.get("requestParameters", {}).get("policyArn"),
            "target_role": detail.get("requestParameters", {}).get("roleName"),
            "target_user": detail.get("requestParameters", {}).get("userName"),
            "event_time": detail.get("eventTime"),
        },
    }
