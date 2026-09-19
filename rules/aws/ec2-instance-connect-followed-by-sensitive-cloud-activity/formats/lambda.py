"""
EC2 Instance Connect Followed by Sensitive Cloud Activity
Trigger: EventBridge rule matching SendSSHPublicKey.
Use for: Correlation from EC2 Instance Connect to later sensitive cloud activity.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ec2-instance-connect.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "SendSSHPublicKey":
        return {"matched": False}

    return {
        "matched": "requires-instance-connect-plus-sensitive-activity-correlation",
        "alert": {
            "rule_id": "det-091",
            "title": "EC2 Instance Connect Followed by Sensitive Cloud Activity",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "instance_id": detail.get("requestParameters", {}).get("instanceId"),
            "event_time": detail.get("eventTime"),
        },
    }
