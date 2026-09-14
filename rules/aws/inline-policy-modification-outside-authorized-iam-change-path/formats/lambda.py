"""
Inline Policy Modification Outside Authorized IAM Change Path
Trigger: EventBridge rule matching PutRolePolicy or PutUserPolicy.
Use for: Real-time triage of IAM changes that require authorization-context enrichment.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "iam.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in ("PutRolePolicy", "PutUserPolicy"):
        return {"matched": False}

    return {
        "matched": "requires-authorized-iam-change-actor-check",
        "alert": {
            "rule_id": "det-033",
            "title": "Inline Policy Modification Outside Authorized IAM Change Path",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "target_role": detail.get("requestParameters", {}).get("roleName"),
            "target_user": detail.get("requestParameters", {}).get("userName"),
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
