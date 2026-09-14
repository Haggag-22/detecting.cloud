"""
EC2 Launch with Instance Profile Outside Authorized Compute Provisioning Path
Trigger: EventBridge rule matching RunInstances.
Use for: Real-time triage of unexpected actors launching compute with attached roles.
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
        "matched": "requires-authorized-compute-launcher-check",
        "alert": {
            "rule_id": "det-067",
            "title": "EC2 Launch with Instance Profile Outside Authorized Compute Provisioning Path",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "instance_profile": request.get("iamInstanceProfile"),
            "event_time": detail.get("eventTime"),
        },
    }
