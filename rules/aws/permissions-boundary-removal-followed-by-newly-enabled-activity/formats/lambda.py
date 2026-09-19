"""
Permissions Boundary Removal Followed by Newly Enabled Activity
Trigger: EventBridge rule matching boundary deletion.
Use for: Correlation with subsequent privileged activity by the actor or affected principal.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "iam.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in ("DeleteRolePermissionsBoundary", "DeleteUserPermissionsBoundary"):
        return {"matched": False}

    return {
        "matched": "requires-correlation-with-follow-on-activity-and-session-lineage",
        "alert": {
            "rule_id": "det-043",
            "title": "Permissions Boundary Removal Followed by Newly Enabled Activity",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "target_role": detail.get("requestParameters", {}).get("roleName"),
            "target_user": detail.get("requestParameters", {}).get("userName"),
            "event_time": detail.get("eventTime"),
        },
    }
