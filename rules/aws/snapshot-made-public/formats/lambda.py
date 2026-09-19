"""
Snapshot Made Public
Trigger: EventBridge rule matching ModifySnapshotAttribute.
Use for: Real-time evaluation of public snapshot exposure.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ec2.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "ModifySnapshotAttribute":
        return {"matched": False}

    return {
        "matched": "requires-public-permission-delta-evaluation",
        "alert": {
            "rule_id": "det-084",
            "title": "Snapshot Made Public",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "snapshot_id": detail.get("requestParameters", {}).get("snapshotId"),
            "event_time": detail.get("eventTime"),
        },
    }
