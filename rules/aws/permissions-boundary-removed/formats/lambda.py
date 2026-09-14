"""
Permissions Boundary Removed
Trigger: EventBridge rule matching DeleteRolePermissionsBoundary or DeleteUserPermissionsBoundary.
Use for: Real-time baseline visibility into boundary deletion.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "iam.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in ("DeleteRolePermissionsBoundary", "DeleteUserPermissionsBoundary"):
        return {"matched": False}

    request = detail.get("requestParameters", {})
    return {
        "matched": True,
        "alert": {
            "rule_id": "det-041",
            "title": "Permissions Boundary Removed",
            "severity": "Medium",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "target_role": request.get("roleName"),
            "target_user": request.get("userName"),
            "event_time": detail.get("eventTime"),
            "source_ip": detail.get("sourceIPAddress"),
        },
    }
