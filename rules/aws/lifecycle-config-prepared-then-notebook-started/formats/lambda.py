"""
Lifecycle Config Prepared Then Notebook Started
Trigger: EventBridge rule matching lifecycle-config changes and notebook starts.
Use for: Stateful correlation of startup-script preparation into notebook execution.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "sagemaker.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in {"CreateNotebookInstanceLifecycleConfig", "UpdateNotebookInstanceLifecycleConfig", "UpdateNotebookInstance", "StartNotebookInstance"}:
        return {"matched": False}

    return {
        "matched": "requires-sagemaker-lifecycle-prep-plus-start-correlation",
        "alert": {
            "rule_id": "det-104",
            "title": "Lifecycle Config Prepared Then Notebook Started",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "event_name": detail.get("eventName"),
            "event_time": detail.get("eventTime"),
        },
    }
