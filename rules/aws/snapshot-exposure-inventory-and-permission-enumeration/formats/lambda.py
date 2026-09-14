"""
Snapshot Exposure Inventory and Permission Enumeration
Trigger: EventBridge rule matching DescribeSnapshotAttribute.
Use for: Visibility into snapshot permission inspection; actual posture control should run on a schedule.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ec2.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "DescribeSnapshotAttribute":
        return {"matched": False}

    request = detail.get("requestParameters", {})
    if request.get("attribute") != "createVolumePermission":
        return {"matched": False}

    return {
        "matched": "permission-enumeration-visibility-only",
        "alert": {
            "rule_id": "det-085",
            "title": "Snapshot Exposure Inventory and Permission Enumeration",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "snapshot_id": request.get("snapshotId"),
            "event_time": detail.get("eventTime"),
        },
    }
