"""
Boundary Changed to Weaker or Non-Standard Boundary
Trigger: EventBridge rule matching PutRolePermissionsBoundary or PutUserPermissionsBoundary.
Use for: Real-time enrichment against exact approved boundary catalog.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "iam.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in ("PutRolePermissionsBoundary", "PutUserPermissionsBoundary"):
        return {"matched": False}

    return {
        "matched": "requires-approved-boundary-catalog-and-before-after-comparison",
        "alert": {
            "rule_id": "det-045",
            "title": "Boundary Changed to Weaker or Non-Standard Boundary",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "new_boundary": detail.get("requestParameters", {}).get("permissionsBoundary"),
            "target_role": detail.get("requestParameters", {}).get("roleName"),
            "target_user": detail.get("requestParameters", {}).get("userName"),
            "event_time": detail.get("eventTime"),
        },
    }
