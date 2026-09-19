"""
ECS Task Definition with External Image
Trigger: EventBridge rule matching RegisterTaskDefinition.
Use for: Real-time triage of unapproved registry usage in ECS task revisions.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ecs.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "RegisterTaskDefinition":
        return {"matched": False}

    containers = detail.get("requestParameters", {}).get("containerDefinitions", [])
    images = [c.get("image", "") for c in containers if c.get("image")]
    suspicious = [img for img in images if any(host in img for host in ["docker.io/", "ghcr.io/", "quay.io/"])]
    if not suspicious:
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-027",
            "title": "ECS Task Definition with External Image",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "task_family": detail.get("requestParameters", {}).get("family"),
            "images": suspicious,
            "task_role": detail.get("requestParameters", {}).get("taskRoleArn"),
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
