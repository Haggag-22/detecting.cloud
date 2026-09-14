"""
Burst SES Identity Enumeration
Trigger: EventBridge rule matching SES identity-enumeration APIs.
Use for: Threshold-based burst detection on SES reconnaissance activity.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ses.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in {"ListIdentities", "GetIdentityVerificationAttributes"}:
        return {"matched": False}

    return {
        "matched": "requires-5-minute-enumeration-threshold-check",
        "alert": {
            "rule_id": "det-107",
            "title": "Burst SES Identity Enumeration",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "event_name": detail.get("eventName"),
            "event_time": detail.get("eventTime"),
        },
    }
