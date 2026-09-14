"""
EBS Volume Not Encrypted
Trigger: EventBridge rule matching CreateVolume.
Use for: Real-time alerting on confirmed or requested unencrypted volume creation.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ec2.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "CreateVolume":
        return {"matched": False}

    request_encrypted = detail.get("requestParameters", {}).get("encrypted")
    response_encrypted = detail.get("responseElements", {}).get("encrypted")
    if request_encrypted is not False and response_encrypted is not False:
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-022",
            "title": "EBS Volume Not Encrypted",
            "severity": "Medium",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "volume_id": detail.get("responseElements", {}).get("volumeId"),
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
