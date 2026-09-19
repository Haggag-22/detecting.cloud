"""
EC2 Instance Connect Outside Authorized Interactive Access Path
Trigger: EventBridge rule matching SendSSHPublicKey.
Use for: Real-time authorization checks for EC2 interactive access.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ec2-instance-connect.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "SendSSHPublicKey":
        return {"matched": False}

    return {
        "matched": "requires-authorized-instance-connect-actor-check",
        "alert": {
            "rule_id": "det-089",
            "title": "EC2 Instance Connect Outside Authorized Interactive Access Path",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "instance_id": detail.get("requestParameters", {}).get("instanceId"),
            "event_time": detail.get("eventTime"),
        },
    }
