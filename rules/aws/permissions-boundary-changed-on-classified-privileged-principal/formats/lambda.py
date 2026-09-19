"""
Permissions Boundary Changed on Classified Privileged Principal
Trigger: EventBridge rule matching PutRolePermissionsBoundary or PutUserPermissionsBoundary.
Use for: Real-time triage of boundary changes on high-value identities.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "iam.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in ("PutRolePermissionsBoundary", "PutUserPermissionsBoundary"):
        return {"matched": False}

    return {
        "matched": "requires-sensitive-principal-classification",
        "alert": {
            "rule_id": "det-046",
            "title": "Permissions Boundary Changed on Classified Privileged Principal",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "target_role": detail.get("requestParameters", {}).get("roleName"),
            "target_user": detail.get("requestParameters", {}).get("userName"),
            "new_boundary": detail.get("requestParameters", {}).get("permissionsBoundary"),
            "event_time": detail.get("eventTime"),
        },
    }
