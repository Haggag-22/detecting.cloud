"""
IAM User Policy Attachment
Trigger: EventBridge rule matching AttachUserPolicy or PutUserPolicy.
Use for: Real-time alerting on direct-to-user privilege grants.
"""

SENSITIVE_MANAGED = ("AdministratorAccess", "IAMFullAccess", "PowerUserAccess")
RISKY_INLINE = ("iam:PassRole", "sts:AssumeRole", "secretsmanager:GetSecretValue", "kms:Decrypt", '"Action":"*"')

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "iam.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in ("AttachUserPolicy", "PutUserPolicy"):
        return {"matched": False}

    request = detail.get("requestParameters", {})
    policy_arn = request.get("policyArn", "")
    policy_document = request.get("policyDocument", "")

    if not any(x in policy_arn for x in SENSITIVE_MANAGED) and not any(x in policy_document for x in RISKY_INLINE):
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-004",
            "title": "IAM User Policy Attachment",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "target_user": request.get("userName"),
            "policy_arn": policy_arn,
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
