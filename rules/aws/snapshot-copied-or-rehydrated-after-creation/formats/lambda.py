"""
Snapshot Copied or Rehydrated After Creation
Trigger: EventBridge rule matching snapshot creation, copy, and restore events.
Use for: State-based lineage correlation from snapshot creation to copy or volume rehydration.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ec2.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in {"CreateSnapshot", "CreateSnapshots", "CopySnapshot", "CreateVolume", "AttachVolume"}:
        return {"matched": False}

    return {
        "matched": "requires-snapshot-lineage-correlation",
        "alert": {
            "rule_id": "det-082",
            "title": "Snapshot Copied or Rehydrated After Creation",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "event_name": detail.get("eventName"),
            "event_time": detail.get("eventTime"),
        },
    }
