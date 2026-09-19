"""
EKS Access Entry Created
Trigger: EventBridge rule matching CreateAccessEntry.
Use for: Baseline visibility into new EKS access-entry creation.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "eks.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "CreateAccessEntry":
        return {"matched": False}

    request = detail.get("requestParameters", {})
    return {
        "matched": True,
        "alert": {
            "rule_id": "det-096",
            "title": "EKS Access Entry Created",
            "severity": "Medium",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "cluster": request.get("clusterName"),
            "principal_arn": request.get("principalArn"),
            "event_time": detail.get("eventTime"),
        },
    }
