"""
Lifecycle Config Associated to Notebook Instance
Trigger: EventBridge rule matching notebook create or update events.
Use for: Real-time visibility into operational lifecycle-config attachment.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "sagemaker.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in {"CreateNotebookInstance", "UpdateNotebookInstance"}:
        return {"matched": False}

    request = detail.get("requestParameters", {})
    if not request.get("lifecycleConfigName"):
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-102",
            "title": "Lifecycle Config Associated to Notebook Instance",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "notebook_name": request.get("notebookInstanceName"),
            "lifecycle_config_name": request.get("lifecycleConfigName"),
            "event_name": detail.get("eventName"),
            "event_time": detail.get("eventTime"),
        },
    }
