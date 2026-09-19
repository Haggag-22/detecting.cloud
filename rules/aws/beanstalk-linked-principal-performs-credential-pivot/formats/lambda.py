"""
Beanstalk-Linked Principal Performs Credential Pivot
Trigger: EventBridge rule matching CreateAccessKey or AssumeRole.
Use for: Real-time evaluation of credential pivots from Beanstalk-linked principals.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    event_source = detail.get("eventSource")
    event_name = detail.get("eventName")
    if (event_source, event_name) not in {
        ("iam.amazonaws.com", "CreateAccessKey"),
        ("sts.amazonaws.com", "AssumeRole"),
    }:
        return {"matched": False}

    return {
        "matched": "requires-beanstalk-principal-linkage-check",
        "alert": {
            "rule_id": "det-118",
            "title": "Beanstalk-Linked Principal Performs Credential Pivot",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "event_name": event_name,
            "event_time": detail.get("eventTime"),
        },
    }
