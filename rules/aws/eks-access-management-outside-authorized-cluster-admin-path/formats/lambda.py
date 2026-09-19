"""
EKS Access Management Outside Authorized Cluster Admin Path
Trigger: EventBridge rule matching CreateAccessEntry or AssociateAccessPolicy.
Use for: Real-time authorization checks for EKS access-management changes.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "eks.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in {"CreateAccessEntry", "AssociateAccessPolicy"}:
        return {"matched": False}

    request = detail.get("requestParameters", {})
    return {
        "matched": "requires-authorized-eks-access-manager-check",
        "alert": {
            "rule_id": "det-100",
            "title": "EKS Access Management Outside Authorized Cluster Admin Path",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "cluster": request.get("clusterName"),
            "principal_arn": request.get("principalArn"),
            "event_name": detail.get("eventName"),
            "event_time": detail.get("eventTime"),
        },
    }
