"""
SES Identity Enumeration Outside Authorized Messaging Path
Trigger: EventBridge rule matching SES identity-enumeration APIs.
Use for: Real-time authorization checks on SES reconnaissance activity.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ses.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in {"ListIdentities", "GetIdentityVerificationAttributes"}:
        return {"matched": False}

    return {
        "matched": "requires-authorized-ses-identity-reader-check",
        "alert": {
            "rule_id": "det-108",
            "title": "SES Identity Enumeration Outside Authorized Messaging Path",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "event_name": detail.get("eventName"),
            "event_time": detail.get("eventTime"),
        },
    }
