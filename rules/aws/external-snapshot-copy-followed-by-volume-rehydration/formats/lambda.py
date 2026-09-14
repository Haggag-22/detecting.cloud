"""
External Snapshot Copy Followed by Volume Rehydration
Trigger: EventBridge rule matching CopySnapshot, CreateVolume, and AttachVolume.
Use for: Stateful lineage correlation from copied snapshot to restored or attached volume.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ec2.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in {"CopySnapshot", "CreateVolume", "AttachVolume"}:
        return {"matched": False}

    return {
        "matched": "requires-copy-to-volume-lineage-correlation",
        "alert": {
            "rule_id": "det-087",
            "title": "External Snapshot Copy Followed by Volume Rehydration",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "event_name": detail.get("eventName"),
            "event_time": detail.get("eventTime"),
        },
    }
