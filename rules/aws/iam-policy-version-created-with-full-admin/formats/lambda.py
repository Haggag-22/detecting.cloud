"""
IAM Policy Version Created with Full Admin
Trigger: EventBridge rule matching CloudTrail CreatePolicyVersion events.
Use for: Real-time alerting when a managed policy is updated to broad admin permissions.
"""

import json

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "iam.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "CreatePolicyVersion":
        return {"matched": False}

    request = detail.get("requestParameters", {})
    policy_document = request.get("policyDocument", "")
    set_as_default = request.get("setAsDefault", False)

    if not set_as_default:
        return {"matched": False}
    if '"Action":"*"' not in policy_document or '"Resource":"*"' not in policy_document:
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-011",
            "title": "IAM Policy Version Created with Full Admin",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "policy_arn": request.get("policyArn"),
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
