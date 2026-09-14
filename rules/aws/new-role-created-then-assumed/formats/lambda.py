"""
New Role Created Then Assumed
Trigger: EventBridge rule matching CreateRole or AssumeRole.
Use for: Correlation of new role creation with near-term successful use.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    event_source = detail.get("eventSource")
    event_name = detail.get("eventName")
    if event_source not in {"iam.amazonaws.com", "sts.amazonaws.com"}:
        return {"matched": False}
    if event_name not in {"CreateRole", "AssumeRole"}:
        return {"matched": False}

    return {
        "matched": "requires-createrole-plus-assumerole-correlation",
        "alert": {
            "rule_id": "det-064",
            "title": "New Role Created Then Assumed",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "role_name": detail.get("requestParameters", {}).get("roleName"),
            "role_arn": detail.get("requestParameters", {}).get("roleArn"),
            "event_name": event_name,
            "event_time": detail.get("eventTime"),
        },
    }
