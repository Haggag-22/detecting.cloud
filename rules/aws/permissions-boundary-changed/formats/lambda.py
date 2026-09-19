"""
Permissions Boundary Changed
Trigger: EventBridge rule matching PutRolePermissionsBoundary or PutUserPermissionsBoundary.
Use for: Baseline visibility into boundary assignment and replacement.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "iam.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in ("PutRolePermissionsBoundary", "PutUserPermissionsBoundary"):
        return {"matched": False}

    request = detail.get("requestParameters", {})
    return {
        "matched": True,
        "alert": {
            "rule_id": "det-044",
            "title": "Permissions Boundary Changed",
            "severity": "Medium",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "target_role": request.get("roleName"),
            "target_user": request.get("userName"),
            "new_boundary": request.get("permissionsBoundary"),
            "event_time": detail.get("eventTime"),
        },
    }
