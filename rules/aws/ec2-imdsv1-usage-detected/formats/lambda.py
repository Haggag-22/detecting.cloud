"""
EC2 IMDSv1 Usage Detected
Trigger: EventBridge rule matching RunInstances or ModifyInstanceMetadataOptions.
Use for: Real-time exposure detection when IMDSv2 is not enforced.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    event_name = detail.get("eventName")

    if detail.get("eventSource") != "ec2.amazonaws.com":
        return {"matched": False}

    http_tokens = None
    if event_name == "RunInstances":
        http_tokens = detail.get("requestParameters", {}).get("metadataOptions", {}).get("httpTokens")
    elif event_name == "ModifyInstanceMetadataOptions":
        http_tokens = detail.get("requestParameters", {}).get("httpTokens")

    if http_tokens != "optional":
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-015",
            "title": "EC2 IMDSv1 Usage Detected",
            "severity": "Medium",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "event_name": event_name,
            "instance_id": detail.get("requestParameters", {}).get("instanceId"),
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
