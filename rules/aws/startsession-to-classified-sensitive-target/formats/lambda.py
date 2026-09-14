"""
StartSession to Classified Sensitive Target
Trigger: EventBridge rule matching StartSession.
Use for: Real-time target sensitivity enrichment on interactive access.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ssm.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "StartSession":
        return {"matched": False}

    return {
        "matched": "requires-target-sensitivity-classification",
        "alert": {
            "rule_id": "det-077",
            "title": "StartSession to Classified Sensitive Target",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "target": detail.get("requestParameters", {}).get("target"),
            "event_time": detail.get("eventTime"),
        },
    }
