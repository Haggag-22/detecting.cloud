"""
EKS Access Entry Followed by Access Policy Association
Trigger: EventBridge rule matching CreateAccessEntry and AssociateAccessPolicy.
Use for: Stateful correlation of EKS access onboarding into effective authorization.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "eks.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in {"CreateAccessEntry", "AssociateAccessPolicy"}:
        return {"matched": False}

    request = detail.get("requestParameters", {})
    return {
        "matched": "requires-access-entry-plus-policy-association-correlation",
        "alert": {
            "rule_id": "det-099",
            "title": "EKS Access Entry Followed by Access Policy Association",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "cluster": request.get("clusterName"),
            "principal_arn": request.get("principalArn"),
            "event_name": detail.get("eventName"),
            "event_time": detail.get("eventTime"),
        },
    }
