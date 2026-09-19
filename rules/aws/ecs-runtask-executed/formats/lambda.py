"""
ECS RunTask Executed
Trigger: EventBridge rule matching RunTask.
Use for: Baseline visibility into ad hoc task execution and task-role activation.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ecs.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "RunTask":
        return {"matched": False}

    request = detail.get("requestParameters", {})
    return {
        "matched": True,
        "alert": {
            "rule_id": "det-070",
            "title": "ECS RunTask Executed",
            "severity": "Medium",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "cluster": request.get("cluster"),
            "task_definition": request.get("taskDefinition"),
            "event_time": detail.get("eventTime"),
            "source_ip": detail.get("sourceIPAddress"),
        },
    }
