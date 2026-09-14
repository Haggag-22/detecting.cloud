"""
Restrictive IAM Control Removed or Weakened
Trigger: EventBridge rule matching policy removals or boundary-removal events.
Use for: Semantic control-reduction triage with prior-state enrichment.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "iam.amazonaws.com":
        return {"matched": False}

    supported = (
        "DetachUserPolicy",
        "DetachRolePolicy",
        "DeleteUserPolicy",
        "DeleteRolePolicy",
        "DeleteRolePermissionsBoundary",
        "DeleteUserPermissionsBoundary",
        "SetDefaultPolicyVersion",
    )
    if detail.get("eventName") not in supported:
        return {"matched": False}

    return {
        "matched": "requires-semantic-control-classification-and-before-after-diff",
        "alert": {
            "rule_id": "det-039",
            "title": "Restrictive IAM Control Removed or Weakened",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "event_name": detail.get("eventName"),
            "event_time": detail.get("eventTime"),
        },
    }
