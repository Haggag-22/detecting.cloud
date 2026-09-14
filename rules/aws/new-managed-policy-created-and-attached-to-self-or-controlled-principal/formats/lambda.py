"""
New Managed Policy Created and Attached to Self or Controlled Principal
Trigger: EventBridge rule matching CreatePolicy and Attach*Policy.
Use for: Correlation of create-and-attach escalation chains.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "iam.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in ("CreatePolicy", "AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy"):
        return {"matched": False}

    return {
        "matched": "requires-correlation-on-created-policy-arn-and-actor",
        "alert": {
            "rule_id": "det-034",
            "title": "New Managed Policy Created and Attached to Self or Controlled Principal",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "event_name": detail.get("eventName"),
            "policy_arn": detail.get("requestParameters", {}).get("policyArn") or detail.get("responseElements", {}).get("policy", {}).get("arn"),
            "event_time": detail.get("eventTime"),
        },
    }
