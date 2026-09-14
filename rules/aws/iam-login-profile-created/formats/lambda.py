"""
IAM Login Profile Created
Trigger: EventBridge rule matching CreateLoginProfile.
Use for: Real-time visibility into console-password creation for IAM users.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "iam.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "CreateLoginProfile":
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-048",
            "title": "IAM Login Profile Created",
            "severity": "Medium",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "target_user": detail.get("requestParameters", {}).get("userName"),
            "event_time": detail.get("eventTime"),
            "source_ip": detail.get("sourceIPAddress"),
        },
    }
