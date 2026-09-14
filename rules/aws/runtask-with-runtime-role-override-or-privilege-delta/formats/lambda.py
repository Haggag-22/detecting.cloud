"""
RunTask with Runtime Role Override or Privilege Delta
Trigger: EventBridge rule matching RunTask.
Use for: Real-time comparison of default and runtime-overridden task roles.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ecs.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "RunTask":
        return {"matched": False}

    return {
        "matched": "requires-task-role-override-diff-analysis",
        "alert": {
            "rule_id": "det-072",
            "title": "RunTask with Runtime Role Override or Privilege Delta",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "cluster": detail.get("requestParameters", {}).get("cluster"),
            "task_definition": detail.get("requestParameters", {}).get("taskDefinition"),
            "event_time": detail.get("eventTime"),
        },
    }
