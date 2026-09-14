"""
Serial Console Followed by Sensitive Recovery or Persistence Activity
Trigger: EventBridge rule matching SendSerialConsoleSSHPublicKey.
Use for: Correlation from serial-console access to later sensitive cloud activity.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ec2-instance-connect.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "SendSerialConsoleSSHPublicKey":
        return {"matched": False}

    return {
        "matched": "requires-serial-console-plus-sensitive-activity-correlation",
        "alert": {
            "rule_id": "det-095",
            "title": "Serial Console Followed by Sensitive Recovery or Persistence Activity",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "instance_id": detail.get("requestParameters", {}).get("instanceId"),
            "event_time": detail.get("eventTime"),
        },
    }
