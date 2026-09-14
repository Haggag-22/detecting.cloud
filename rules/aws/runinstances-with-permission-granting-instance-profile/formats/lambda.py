"""
RunInstances with Permission-Granting Instance Profile
Trigger: EventBridge rule matching RunInstances.
Use for: Real-time enrichment against the backing role behind the instance profile.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ec2.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "RunInstances":
        return {"matched": False}

    request = detail.get("requestParameters", {})
    if not request.get("iamInstanceProfile"):
        return {"matched": False}

    return {
        "matched": "requires-instance-profile-to-role-permission-resolution",
        "alert": {
            "rule_id": "det-066",
            "title": "RunInstances with Permission-Granting Instance Profile",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "instance_profile": request.get("iamInstanceProfile"),
            "event_time": detail.get("eventTime"),
        },
    }
