"""
IAM Role Created
Trigger: EventBridge rule matching CreateRole.
Use for: Baseline visibility into new IAM role creation.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "iam.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "CreateRole":
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-060",
            "title": "IAM Role Created",
            "severity": "Medium",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "role_name": detail.get("requestParameters", {}).get("roleName"),
            "event_time": detail.get("eventTime"),
            "source_ip": detail.get("sourceIPAddress"),
        },
    }
