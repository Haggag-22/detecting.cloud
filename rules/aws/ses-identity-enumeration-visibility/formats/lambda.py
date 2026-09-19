"""
SES Identity Enumeration Visibility
Trigger: EventBridge rule matching SES identity-enumeration APIs.
Use for: Baseline visibility into SES reconnaissance-style reads.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ses.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in {"ListIdentities", "GetIdentityVerificationAttributes"}:
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-106",
            "title": "SES Identity Enumeration Visibility",
            "severity": "Medium",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "event_name": detail.get("eventName"),
            "event_time": detail.get("eventTime"),
        },
    }
