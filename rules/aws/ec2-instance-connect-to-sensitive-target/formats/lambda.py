"""
EC2 Instance Connect to Sensitive Target
Trigger: EventBridge rule matching SendSSHPublicKey.
Use for: Real-time target classification checks for EC2 interactive access.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ec2-instance-connect.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "SendSSHPublicKey":
        return {"matched": False}

    return {
        "matched": "requires-sensitive-target-classification-check",
        "alert": {
            "rule_id": "det-090",
            "title": "EC2 Instance Connect to Sensitive Target",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "instance_id": detail.get("requestParameters", {}).get("instanceId"),
            "event_time": detail.get("eventTime"),
        },
    }
