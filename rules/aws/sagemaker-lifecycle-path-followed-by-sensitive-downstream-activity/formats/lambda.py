"""
SageMaker Lifecycle Path Followed by Sensitive Downstream Activity
Trigger: EventBridge rule matching notebook lifecycle-path events.
Use for: Correlation from SageMaker startup-code execution path to later sensitive cloud activity.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "sagemaker.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in {"UpdateNotebookInstance", "StartNotebookInstance"}:
        return {"matched": False}

    request = detail.get("requestParameters", {})
    return {
        "matched": "requires-sagemaker-lifecycle-plus-sensitive-activity-correlation",
        "alert": {
            "rule_id": "det-105",
            "title": "SageMaker Lifecycle Path Followed by Sensitive Downstream Activity",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "notebook_name": request.get("notebookInstanceName"),
            "event_name": detail.get("eventName"),
            "event_time": detail.get("eventTime"),
        },
    }
