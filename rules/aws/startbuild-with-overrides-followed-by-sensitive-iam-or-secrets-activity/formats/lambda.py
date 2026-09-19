"""
StartBuild with Overrides Followed by Sensitive IAM or Secrets Activity
Trigger: EventBridge rule matching StartBuild.
Use for: Correlation from risky build launch overrides into sensitive cloud activity.
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
        "matched": "requires-codebuild-override-plus-sensitive-activity-correlation",
        "alert": {
            "rule_id": "det-129",
            "title": "StartBuild with Overrides Followed by Sensitive IAM or Secrets Activity",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "project_name": request.get("projectName"),
            "event_time": detail.get("eventTime"),
        },
    }
