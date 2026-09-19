"""
Rare or New Project Used for Build Trigger
Trigger: EventBridge rule matching StartBuild.
Use for: Baseline-aware detection of rare actor-to-project launches.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "codebuild.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "StartBuild":
        return {"matched": False}

    request = detail.get("requestParameters", {})
    return {
        "matched": "requires-actor-project-first-seen-or-rarity-check",
        "alert": {
            "rule_id": "det-200",
            "title": "Rare or New Project Used for Build Trigger",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "project_name": request.get("projectName"),
            "event_time": detail.get("eventTime"),
        },
    }
