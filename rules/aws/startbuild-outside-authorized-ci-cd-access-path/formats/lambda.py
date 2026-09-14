"""
StartBuild Outside Authorized CI/CD Access Path
Trigger: EventBridge rule matching StartBuild.
Use for: Authorization checks on CodeBuild launches.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "codebuild.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "StartBuild":
        return {"matched": False}

    return {
        "matched": "requires-authorized-codebuild-starter-check",
        "alert": {
            "rule_id": "det-128",
            "title": "StartBuild Outside Authorized CI/CD Access Path",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "project_name": detail.get("requestParameters", {}).get("projectName"),
            "event_time": detail.get("eventTime"),
        },
    }
