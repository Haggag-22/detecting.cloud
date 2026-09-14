"""
New or Changed EC2 Role Activation Followed by Sensitive API Use
Trigger: EventBridge rule matching compute role activation events.
Use for: Correlation from role activation on EC2 to later sensitive API use.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ec2.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in {"RunInstances", "AssociateIamInstanceProfile", "ReplaceIamInstanceProfileAssociation"}:
        return {"matched": False}

    return {
        "matched": "requires-profile-to-role-resolution-and-follow-on-role-activity",
        "alert": {
            "rule_id": "det-069",
            "title": "New or Changed EC2 Role Activation Followed by Sensitive API Use",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "instance_profile": detail.get("requestParameters", {}).get("iamInstanceProfile"),
            "event_name": detail.get("eventName"),
            "event_time": detail.get("eventTime"),
        },
    }
