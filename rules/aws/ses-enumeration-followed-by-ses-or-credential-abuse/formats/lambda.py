"""
SES Enumeration Followed by SES or Credential Abuse
Trigger: EventBridge rule matching SES identity-enumeration APIs.
Use for: Correlation from SES reconnaissance to later write or credential abuse.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ses.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in {"ListIdentities", "GetIdentityVerificationAttributes"}:
        return {"matched": False}

    return {
        "matched": "requires-ses-recon-plus-abuse-correlation",
        "alert": {
            "rule_id": "det-109",
            "title": "SES Enumeration Followed by SES or Credential Abuse",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "event_name": detail.get("eventName"),
            "event_time": detail.get("eventTime"),
        },
    }
