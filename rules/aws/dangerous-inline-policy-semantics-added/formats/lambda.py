"""
Dangerous Inline Policy Semantics Added
Trigger: EventBridge rule matching PutRolePolicy or PutUserPolicy.
Use for: Real-time scoring of dangerous inline IAM policy content.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "iam.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in ("PutRolePolicy", "PutUserPolicy"):
        return {"matched": False}

    policy = str(detail.get("requestParameters", {}).get("policyDocument", ""))
    risky_markers = ["iam:*", "sts:AssumeRole", "iam:PassRole", "kms:Decrypt", "secretsmanager:GetSecretValue", '"Action":"*"', '"Resource":"*"']
    if not any(marker in policy for marker in risky_markers):
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-032",
            "title": "Dangerous Inline Policy Semantics Added",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "target_role": detail.get("requestParameters", {}).get("roleName"),
            "target_user": detail.get("requestParameters", {}).get("userName"),
            "policy_name": detail.get("requestParameters", {}).get("policyName"),
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
