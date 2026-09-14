"""
ECS Task Role Activation Followed by Sensitive API Use
Trigger: EventBridge rule matching RunTask.
Use for: Correlation from ECS task launch to later sensitive API activity by the task role.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "ecs.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "RunTask":
        return {"matched": False}

    return {
        "matched": "requires-task-role-resolution-and-follow-on-role-activity",
        "alert": {
            "rule_id": "det-074",
            "title": "ECS Task Role Activation Followed by Sensitive API Use",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "cluster": detail.get("requestParameters", {}).get("cluster"),
            "task_definition": detail.get("requestParameters", {}).get("taskDefinition"),
            "event_time": detail.get("eventTime"),
        },
    }
