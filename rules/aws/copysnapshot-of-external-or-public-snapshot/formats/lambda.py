"""
CopySnapshot of External or Public Snapshot
Trigger: EventBridge rule matching CopySnapshot.
Use for: Real-time evaluation of source snapshot ownership and sharing context.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ec2.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "CopySnapshot":
        return {"matched": False}

    return {
        "matched": "requires-source-snapshot-ownership-and-sharing-check",
        "alert": {
            "rule_id": "det-086",
            "title": "CopySnapshot of External or Public Snapshot",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "source_snapshot_id": detail.get("requestParameters", {}).get("sourceSnapshotId"),
            "event_time": detail.get("eventTime"),
        },
    }
