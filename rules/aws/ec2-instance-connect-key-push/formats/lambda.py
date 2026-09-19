"""
EC2 Instance Connect Key Push
Trigger: EventBridge rule matching SendSSHPublicKey.
Use for: Baseline visibility into EC2 Instance Connect access grants.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ec2-instance-connect.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "SendSSHPublicKey":
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-088",
            "title": "EC2 Instance Connect Key Push",
            "severity": "Medium",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "instance_id": detail.get("requestParameters", {}).get("instanceId"),
            "event_time": detail.get("eventTime"),
        },
    }
