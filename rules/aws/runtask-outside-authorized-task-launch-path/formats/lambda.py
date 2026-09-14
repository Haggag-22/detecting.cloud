"""
RunTask Outside Authorized Task Launch Path
Trigger: EventBridge rule matching RunTask.
Use for: Real-time triage of unauthorized ECS task launches.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ecs.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "RunTask":
        return {"matched": False}

    return {
        "matched": "requires-authorized-task-launcher-check",
        "alert": {
            "rule_id": "det-073",
            "title": "RunTask Outside Authorized Task Launch Path",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "cluster": detail.get("requestParameters", {}).get("cluster"),
            "task_definition": detail.get("requestParameters", {}).get("taskDefinition"),
            "event_time": detail.get("eventTime"),
        },
    }
