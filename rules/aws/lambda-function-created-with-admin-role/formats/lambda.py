"""
Lambda Function Created with Admin Role
Trigger: EventBridge rule matching CloudTrail CreateFunction20150331 events.
Use for: Real-time alerting on Lambda creation with high-risk execution roles.
"""

HIGH_RISK_ROLE_MARKERS = ("Admin", "AdministratorAccess", "PowerUser", "OrganizationAccountAccessRole", "Security")

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "lambda.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "CreateFunction20150331":
        return {"matched": False}

    role_arn = detail.get("requestParameters", {}).get("role", "")
    if not any(marker in role_arn for marker in HIGH_RISK_ROLE_MARKERS):
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-012",
            "title": "Lambda Function Created with Admin Role",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "function_name": detail.get("requestParameters", {}).get("functionName"),
            "role_arn": role_arn,
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
