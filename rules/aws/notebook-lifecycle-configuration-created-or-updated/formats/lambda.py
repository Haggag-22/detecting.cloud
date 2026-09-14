"""
Notebook Lifecycle Configuration Created or Updated
Trigger: EventBridge rule matching lifecycle-config create or update events.
Use for: Baseline visibility into SageMaker startup-script changes.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "sagemaker.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in {"CreateNotebookInstanceLifecycleConfig", "UpdateNotebookInstanceLifecycleConfig"}:
        return {"matched": False}

    request = detail.get("requestParameters", {})
    return {
        "matched": True,
        "alert": {
            "rule_id": "det-101",
            "title": "Notebook Lifecycle Configuration Created or Updated",
            "severity": "Medium",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "lifecycle_config_name": request.get("notebookInstanceLifecycleConfigName"),
            "event_name": detail.get("eventName"),
            "event_time": detail.get("eventTime"),
        },
    }
