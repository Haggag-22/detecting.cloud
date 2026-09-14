"""
IAM PassRole Privilege Escalation via Lambda CreateFunction
Trigger: EventBridge rule matching CloudTrail CreateFunction20150331 events.
Use for: Real-time alerting when callers pass high-risk execution roles to new Lambda functions.
"""

HIGH_RISK_ROLE_MARKERS = ("Admin", "AdministratorAccess", "PowerUser", "OrganizationAccountAccessRole")

def lambda_handler(event, context):
    detail = event.get("detail", {})
    role_arn = detail.get("requestParameters", {}).get("role", "")

    if detail.get("eventSource") != "lambda.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "CreateFunction20150331":
        return {"matched": False}
    if not any(marker in role_arn for marker in HIGH_RISK_ROLE_MARKERS):
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-001",
            "title": "IAM PassRole Privilege Escalation",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "function_name": detail.get("requestParameters", {}).get("functionName"),
            "passed_role": role_arn,
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
