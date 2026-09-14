"""
SageMaker Lifecycle Management Outside Authorized ML Platform Path
Trigger: EventBridge rule matching SageMaker lifecycle-config and notebook-association changes.
Use for: Real-time authorization checks on SageMaker startup-logic management.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "sagemaker.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in {"CreateNotebookInstanceLifecycleConfig", "UpdateNotebookInstanceLifecycleConfig", "CreateNotebookInstance", "UpdateNotebookInstance"}:
        return {"matched": False}

    return {
        "matched": "requires-authorized-sagemaker-lifecycle-manager-check",
        "alert": {
            "rule_id": "det-103",
            "title": "SageMaker Lifecycle Management Outside Authorized ML Platform Path",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "event_name": detail.get("eventName"),
            "event_time": detail.get("eventTime"),
        },
    }
