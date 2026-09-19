"""
KMS Key Scheduled for Deletion
Trigger: EventBridge rule matching ScheduleKeyDeletion.
Use for: Real-time alerting on destructive KMS lifecycle actions.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "kms.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "ScheduleKeyDeletion":
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-019",
            "title": "KMS Key Scheduled for Deletion",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "key_id": detail.get("requestParameters", {}).get("keyId"),
            "pending_window_days": detail.get("requestParameters", {}).get("pendingWindowInDays"),
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
