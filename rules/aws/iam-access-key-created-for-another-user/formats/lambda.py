"""
IAM Access Key Created for Another User
Trigger: EventBridge rule matching CreateAccessKey.
Use for: Real-time alerting on explicit cross-user key provisioning.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "iam.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "CreateAccessKey":
        return {"matched": False}

    request = detail.get("requestParameters", {})
    target_user = request.get("userName")
    if not target_user:
        return {"matched": False}

    actor = detail.get("userIdentity", {})
    actor_type = actor.get("type")
    actor_user = actor.get("userName")

    if actor_type == "IAMUser" and actor_user == target_user:
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-010",
            "title": "IAM Access Key Created for Another User",
            "severity": "High",
            "actor": actor.get("arn"),
            "target_user": target_user,
            "access_key_id": detail.get("responseElements", {}).get("accessKey", {}).get("accessKeyId"),
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
