"""
Access Policy Association Grants Broad Cluster Access
Trigger: EventBridge rule matching AssociateAccessPolicy.
Use for: Real-time evaluation of EKS policy semantics and effective access scope.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "eks.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "AssociateAccessPolicy":
        return {"matched": False}

    request = detail.get("requestParameters", {})
    return {
        "matched": "requires-eks-policy-semantics-and-scope-evaluation",
        "alert": {
            "rule_id": "det-098",
            "title": "Access Policy Association Grants Broad Cluster Access",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "cluster": request.get("clusterName"),
            "principal_arn": request.get("principalArn"),
            "policy_arn": request.get("policyArn"),
            "event_time": detail.get("eventTime"),
        },
    }
