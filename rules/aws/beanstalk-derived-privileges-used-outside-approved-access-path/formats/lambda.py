"""
Beanstalk-Derived Privileges Used Outside Approved Access Path
Trigger: EventBridge rule matching CreateAccessKey or AssumeRole.
Use for: Authorization checks on Beanstalk-linked IAM or STS pivots.
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
        "matched": "requires-authorized-beanstalk-pivot-actor-check",
        "alert": {
            "rule_id": "det-121",
            "title": "Beanstalk-Derived Privileges Used Outside Approved Access Path",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "event_name": event_name,
            "event_time": detail.get("eventTime"),
        },
    }
