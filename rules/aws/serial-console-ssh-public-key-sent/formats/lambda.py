"""
Serial Console SSH Public Key Sent
Trigger: EventBridge rule matching SendSerialConsoleSSHPublicKey.
Use for: Baseline visibility into serial console access.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ec2-instance-connect.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "SendSerialConsoleSSHPublicKey":
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-092",
            "title": "Serial Console SSH Public Key Sent",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "instance_id": detail.get("requestParameters", {}).get("instanceId"),
            "event_time": detail.get("eventTime"),
        },
    }
