"""
Beanstalk Recon Followed by CreateAccessKey for High-Risk Target
Trigger: EventBridge rule matching CreateAccessKey.
Use for: Correlation from Beanstalk recon into creation of access keys for high-risk identities.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "iam.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "CreateAccessKey":
        return {"matched": False}

    return {
        "matched": "requires-beanstalk-recon-plus-high-risk-createaccesskey-correlation",
        "alert": {
            "rule_id": "det-120",
            "title": "Beanstalk Recon Followed by CreateAccessKey for High-Risk Target",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "target_user": detail.get("requestParameters", {}).get("userName"),
            "event_time": detail.get("eventTime"),
        },
    }
