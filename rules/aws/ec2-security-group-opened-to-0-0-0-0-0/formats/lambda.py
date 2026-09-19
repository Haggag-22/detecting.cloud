"""
EC2 Security Group Opened to 0.0.0.0/0
Trigger: EventBridge rule matching AuthorizeSecurityGroupIngress.
Use for: Real-time alerting on public IPv4 ingress exposure.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ec2.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "AuthorizeSecurityGroupIngress":
        return {"matched": False}

    permissions = str(detail.get("requestParameters", {}).get("ipPermissions", ""))
    if "0.0.0.0/0" not in permissions:
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-016",
            "title": "EC2 Security Group Opened to 0.0.0.0/0",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "group_id": detail.get("requestParameters", {}).get("groupId"),
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
