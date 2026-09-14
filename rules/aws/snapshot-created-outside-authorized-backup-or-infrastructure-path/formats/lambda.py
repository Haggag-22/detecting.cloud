"""
Snapshot Created Outside Authorized Backup or Infrastructure Path
Trigger: EventBridge rule matching CreateSnapshot or CreateSnapshots.
Use for: Real-time triage of unauthorized snapshot creation.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ec2.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in {"CreateSnapshot", "CreateSnapshots"}:
        return {"matched": False}

    return {
        "matched": "requires-authorized-snapshot-actor-check",
        "alert": {
            "rule_id": "det-080",
            "title": "Snapshot Created Outside Authorized Backup or Infrastructure Path",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "volume_id": detail.get("requestParameters", {}).get("volumeId"),
            "event_name": detail.get("eventName"),
            "event_time": detail.get("eventTime"),
        },
    }
