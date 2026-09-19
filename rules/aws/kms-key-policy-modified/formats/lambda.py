"""
KMS Key Policy Modified
Trigger: EventBridge rule matching PutKeyPolicy.
Use for: Real-time parsing of risky KMS policy changes.
"""

RISKY_POLICY_MARKERS = ('"Principal":"*"', '"Principal":{"AWS":"*"}', ':root"', '"kms:*"', '"kms:Decrypt"', '"kms:GenerateDataKey', '"kms:CreateGrant"', '"kms:PutKeyPolicy"', '"kms:ScheduleKeyDeletion"')

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "kms.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "PutKeyPolicy":
        return {"matched": False}

    request = detail.get("requestParameters", {})
    policy = request.get("policy", "")
    bypass = request.get("bypassPolicyLockoutSafetyCheck", False)

    if not bypass and not any(marker in policy for marker in RISKY_POLICY_MARKERS):
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-020",
            "title": "KMS Key Policy Modified",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "key_id": request.get("keyId"),
            "policy_name": request.get("policyName"),
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
