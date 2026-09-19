"""
EC2 Instance with Highly Privileged IAM Role
Trigger: EventBridge rule matching RunInstances.
Use for: Real-time alerting on EC2 launches with high-risk instance profiles.
"""

HIGH_RISK_PROFILE_MARKERS = ("Admin", "Administrator", "PowerUser", "Security", "OrganizationAccountAccessRole")

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ec2.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "RunInstances":
        return {"matched": False}

    profile_arn = detail.get("requestParameters", {}).get("iamInstanceProfile", {}).get("arn", "")
    if not any(marker in profile_arn for marker in HIGH_RISK_PROFILE_MARKERS):
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-014",
            "title": "EC2 Instance with Highly Privileged IAM Role",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "profile_arn": profile_arn,
            "instance_type": detail.get("requestParameters", {}).get("instanceType"),
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
