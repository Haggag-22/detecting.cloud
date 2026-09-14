"""
Snapshot Shared to External Account
Trigger: EventBridge rule matching ModifySnapshotAttribute.
Use for: Real-time evaluation of snapshot recipient-account exposure.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ec2.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "ModifySnapshotAttribute":
        return {"matched": False}

    return {
        "matched": "requires-external-account-recipient-evaluation",
        "alert": {
            "rule_id": "det-081",
            "title": "Snapshot Shared to External Account",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "snapshot_id": detail.get("requestParameters", {}).get("snapshotId"),
            "event_time": detail.get("eventTime"),
        },
    }
