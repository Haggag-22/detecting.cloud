"""
Serial Console Access to Sensitive Target
Trigger: EventBridge rule matching SendSerialConsoleSSHPublicKey.
Use for: Real-time sensitive-target checks for serial-console access.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ec2-instance-connect.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "SendSerialConsoleSSHPublicKey":
        return {"matched": False}

    return {
        "matched": "requires-sensitive-serial-console-target-check",
        "alert": {
            "rule_id": "det-094",
            "title": "Serial Console Access to Sensitive Target",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "instance_id": detail.get("requestParameters", {}).get("instanceId"),
            "event_time": detail.get("eventTime"),
        },
    }
