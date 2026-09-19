"""
EC2 Instance Profile Associated or Replaced
Trigger: EventBridge rule matching AssociateIamInstanceProfile or ReplaceIamInstanceProfileAssociation.
Use for: Baseline visibility into profile changes on existing instances.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ec2.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in {"AssociateIamInstanceProfile", "ReplaceIamInstanceProfileAssociation"}:
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-068",
            "title": "EC2 Instance Profile Associated or Replaced",
            "severity": "Medium",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "instance_id": detail.get("requestParameters", {}).get("instanceId"),
            "instance_profile": detail.get("requestParameters", {}).get("iamInstanceProfile"),
            "event_name": detail.get("eventName"),
            "event_time": detail.get("eventTime"),
        },
    }
