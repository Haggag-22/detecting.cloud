"""
Snapshot Loot Chain
Trigger: EventBridge rule matching snapshot creation, sharing, copying, and rehydration events.
Use for: Stateful multi-step detection of snapshot exposure and restore workflows.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ec2.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in {"CreateSnapshot", "CreateSnapshots", "ModifySnapshotAttribute", "CopySnapshot", "CreateVolume", "AttachVolume"}:
        return {"matched": False}

    return {
        "matched": "requires-multi-stage-snapshot-loot-chain-correlation",
        "alert": {
            "rule_id": "det-083",
            "title": "Snapshot Loot Chain",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "event_name": detail.get("eventName"),
            "event_time": detail.get("eventTime"),
        },
    }
