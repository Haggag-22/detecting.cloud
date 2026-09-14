"""
Managed Policy Default Version Switched to More Permissive Version
Trigger: EventBridge rule matching SetDefaultPolicyVersion.
Use for: Real-time enrichment against prior default version and policy diff.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "iam.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "SetDefaultPolicyVersion":
        return {"matched": False}

    return {
        "matched": "requires-prior-default-version-and-diff",
        "alert": {
            "rule_id": "det-035",
            "title": "Managed Policy Default Version Switched to More Permissive Version",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "policy_arn": detail.get("requestParameters", {}).get("policyArn"),
            "version_id": detail.get("requestParameters", {}).get("versionId"),
            "event_time": detail.get("eventTime"),
        },
    }
