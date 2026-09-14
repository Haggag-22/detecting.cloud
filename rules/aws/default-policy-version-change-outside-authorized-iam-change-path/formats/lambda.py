"""
Default Policy Version Change Outside Authorized IAM Change Path
Trigger: EventBridge rule matching SetDefaultPolicyVersion.
Use for: Real-time triage of policy-version changes requiring authorization-context enrichment.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "iam.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "SetDefaultPolicyVersion":
        return {"matched": False}

    return {
        "matched": "requires-authorized-policy-version-manager-check",
        "alert": {
            "rule_id": "det-037",
            "title": "Default Policy Version Change Outside Authorized IAM Change Path",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "policy_arn": detail.get("requestParameters", {}).get("policyArn"),
            "version_id": detail.get("requestParameters", {}).get("versionId"),
            "event_time": detail.get("eventTime"),
        },
    }
