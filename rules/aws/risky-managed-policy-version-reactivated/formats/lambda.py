"""
Risky Managed Policy Version Reactivated
Trigger: EventBridge rule matching SetDefaultPolicyVersion.
Use for: Real-time enrichment against policy version catalog and prior default version.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "iam.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "SetDefaultPolicyVersion":
        return {"matched": False}

    return {
        "matched": "requires-policy-version-catalog-and-risk-classification",
        "alert": {
            "rule_id": "det-036",
            "title": "Risky Managed Policy Version Reactivated",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "policy_arn": detail.get("requestParameters", {}).get("policyArn"),
            "version_id": detail.get("requestParameters", {}).get("versionId"),
            "event_time": detail.get("eventTime"),
        },
    }
