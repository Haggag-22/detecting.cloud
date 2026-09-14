"""
RunTask with Permission-Granting Task Role
Trigger: EventBridge rule matching RunTask.
Use for: Real-time task-role resolution and permission scoring.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ecs.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "RunTask":
        return {"matched": False}

    return {
        "matched": "requires-resolved-task-role-permission-classification",
        "alert": {
            "rule_id": "det-071",
            "title": "RunTask with Permission-Granting Task Role",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "cluster": detail.get("requestParameters", {}).get("cluster"),
            "task_definition": detail.get("requestParameters", {}).get("taskDefinition"),
            "event_time": detail.get("eventTime"),
        },
    }
