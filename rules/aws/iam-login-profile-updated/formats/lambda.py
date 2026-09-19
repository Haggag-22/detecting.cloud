"""
IAM Login Profile Updated
Trigger: EventBridge rule matching UpdateLoginProfile.
Use for: Baseline visibility into IAM password reset or console-password update events.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "iam.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "UpdateLoginProfile":
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-052",
            "title": "IAM Login Profile Updated",
            "severity": "Medium",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "target_user": detail.get("requestParameters", {}).get("userName"),
            "event_time": detail.get("eventTime"),
            "source_ip": detail.get("sourceIPAddress"),
        },
    }
