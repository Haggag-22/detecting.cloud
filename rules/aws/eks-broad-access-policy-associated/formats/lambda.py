"""
EKS Broad Access Policy Associated
Trigger: EventBridge rule matching AssociateAccessPolicy.
Use for: Real-time alerting on broad EKS authorization grants.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "eks.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "AssociateAccessPolicy":
        return {"matched": False}

    request = detail.get("requestParameters", {})
    policy_arn = request.get("policyArn", "")
    access_scope = request.get("accessScope", {}).get("type")
    if access_scope != "cluster":
        return {"matched": False}
    if "AmazonEKSClusterAdminPolicy" not in policy_arn and "AmazonEKSAdminPolicy" not in policy_arn:
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-026",
            "title": "EKS Broad Access Policy Associated",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "cluster_name": request.get("clusterName"),
            "target_principal": request.get("principalArn"),
            "policy_arn": policy_arn,
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
