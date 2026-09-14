"""
StartBuild with Dangerous Overrides
Trigger: EventBridge rule matching StartBuild.
Use for: Real-time detection of high-risk build launch overrides.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "codebuild.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "StartBuild":
        return {"matched": False}

    request = detail.get("requestParameters", {})
    if not (request.get("buildspecOverride") or request.get("environmentVariablesOverride")):
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-127",
            "title": "StartBuild with Dangerous Overrides",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "project_name": request.get("projectName"),
            "event_time": detail.get("eventTime"),
        },
    }
