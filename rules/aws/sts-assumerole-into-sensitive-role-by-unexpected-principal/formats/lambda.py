"""
STS AssumeRole into Sensitive Role by Unexpected Principal
Trigger: EventBridge rule matching CloudTrail AssumeRole events.
Use for: Real-time alerting on suspicious role assumption into sensitive roles.
"""

SENSITIVE_ROLE_MARKERS = ("Admin", "Administrator", "PowerUser", "OrganizationAccountAccessRole", "Security")
APPROVED_CALLER_MARKERS = ("/role/Admin", "/role/Security", "/role/Platform", "/role/Infra", "AWSReservedSSO_AdministratorAccess")

def lambda_handler(event, context):
    detail = event.get("detail", {})
    caller = detail.get("userIdentity", {}).get("arn", "")
    role_arn = detail.get("requestParameters", {}).get("roleArn", "")

    if detail.get("eventSource") != "sts.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "AssumeRole":
        return {"matched": False}
    if not any(marker in role_arn for marker in SENSITIVE_ROLE_MARKERS):
        return {"matched": False}
    if any(marker in caller for marker in APPROVED_CALLER_MARKERS):
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-130",
            "title": "STS AssumeRole into Sensitive Role by Unexpected Principal",
            "severity": "Critical",
            "actor": caller,
            "target_role": role_arn,
            "session_name": detail.get("requestParameters", {}).get("roleSessionName"),
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
