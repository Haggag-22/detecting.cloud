"""
CodeBuild StartBuild Visibility
Trigger: EventBridge rule matching StartBuild.
Use for: Baseline visibility into CodeBuild execution requests.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "codebuild.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "StartBuild":
        return {"matched": False}

    request = detail.get("requestParameters", {})
    return {
        "matched": True,
        "alert": {
            "rule_id": "det-126",
            "title": "CodeBuild StartBuild Visibility",
            "severity": "Medium",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "project_name": request.get("projectName"),
            "event_time": detail.get("eventTime"),
        },
    }
