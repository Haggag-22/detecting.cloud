"""
Access Entry Created for Principal Outside Approved Kubernetes Access Model
Trigger: EventBridge rule matching CreateAccessEntry.
Use for: Real-time evaluation of principal suitability for cluster access.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "eks.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "CreateAccessEntry":
        return {"matched": False}

    request = detail.get("requestParameters", {})
    return {
        "matched": "requires-approved-kubernetes-principal-check",
        "alert": {
            "rule_id": "det-097",
            "title": "Access Entry Created for Principal Outside Approved Kubernetes Access Model",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "cluster": request.get("clusterName"),
            "principal_arn": request.get("principalArn"),
            "event_time": detail.get("eventTime"),
        },
    }
