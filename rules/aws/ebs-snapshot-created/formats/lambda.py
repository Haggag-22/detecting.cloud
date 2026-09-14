"""
EBS Snapshot Created
Trigger: EventBridge rule matching CreateSnapshot or CreateSnapshots.
Use for: Baseline visibility into snapshot creation activity.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ec2.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in {"CreateSnapshot", "CreateSnapshots"}:
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-079",
            "title": "EBS Snapshot Created",
            "severity": "Medium",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "volume_id": detail.get("requestParameters", {}).get("volumeId"),
            "event_name": detail.get("eventName"),
            "event_time": detail.get("eventTime"),
        },
    }
