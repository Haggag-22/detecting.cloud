"""
Boundary Weakened Followed by Newly Enabled Activity
Trigger: EventBridge rule matching PutRolePermissionsBoundary or PutUserPermissionsBoundary.
Use for: Correlation of weakening changes with subsequent high-risk activity.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "iam.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in ("PutRolePermissionsBoundary", "PutUserPermissionsBoundary"):
        return {"matched": False}

    return {
        "matched": "requires-boundary-diff-and-follow-on-correlation",
        "alert": {
            "rule_id": "det-047",
            "title": "Boundary Weakened Followed by Newly Enabled Activity",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "target_role": detail.get("requestParameters", {}).get("roleName"),
            "target_user": detail.get("requestParameters", {}).get("userName"),
            "new_boundary": detail.get("requestParameters", {}).get("permissionsBoundary"),
            "event_time": detail.get("eventTime"),
        },
    }
