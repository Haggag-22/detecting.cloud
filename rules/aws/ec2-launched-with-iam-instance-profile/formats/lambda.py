"""
EC2 Launched with IAM Instance Profile
Trigger: EventBridge rule matching RunInstances.
Use for: Baseline visibility into compute launches that activate IAM roles.
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
        "matched": True,
        "alert": {
            "rule_id": "det-065",
            "title": "EC2 Launched with IAM Instance Profile",
            "severity": "Medium",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "instance_profile": request.get("iamInstanceProfile"),
            "event_time": detail.get("eventTime"),
            "source_ip": detail.get("sourceIPAddress"),
        },
    }
