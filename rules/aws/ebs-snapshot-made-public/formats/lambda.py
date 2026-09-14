"""
EBS Snapshot Made Public
Trigger: EventBridge rule matching ModifySnapshotAttribute.
Use for: Real-time alerting on public EBS snapshot exposure.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ec2.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "ModifySnapshotAttribute":
        return {"matched": False}

    request = str(detail.get("requestParameters", {}))
    if '"group":"all"' not in request and "groupNames" not in request:
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-021",
            "title": "EBS Snapshot Made Public",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "snapshot_id": detail.get("requestParameters", {}).get("snapshotId"),
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
