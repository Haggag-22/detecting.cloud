"""
Serial Console Access Outside Authorized Recovery Path
Trigger: EventBridge rule matching SendSerialConsoleSSHPublicKey.
Use for: Real-time authorization checks for serial-console access.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ec2-instance-connect.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "SendSerialConsoleSSHPublicKey":
        return {"matched": False}

    return {
        "matched": "requires-authorized-serial-console-actor-check",
        "alert": {
            "rule_id": "det-093",
            "title": "Serial Console Access Outside Authorized Recovery Path",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "instance_id": detail.get("requestParameters", {}).get("instanceId"),
            "event_time": detail.get("eventTime"),
        },
    }
