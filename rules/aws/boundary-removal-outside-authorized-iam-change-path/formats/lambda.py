"""
Boundary Removal Outside Authorized IAM Change Path
Trigger: EventBridge rule matching DeleteRolePermissionsBoundary or DeleteUserPermissionsBoundary.
Use for: Real-time triage of unauthorized boundary deletions.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "iam.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in ("DeleteRolePermissionsBoundary", "DeleteUserPermissionsBoundary"):
        return {"matched": False}

    return {
        "matched": "requires-authorized-boundary-manager-check",
        "alert": {
            "rule_id": "det-042",
            "title": "Boundary Removal Outside Authorized IAM Change Path",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "target_role": detail.get("requestParameters", {}).get("roleName"),
            "target_user": detail.get("requestParameters", {}).get("userName"),
            "event_time": detail.get("eventTime"),
        },
    }
