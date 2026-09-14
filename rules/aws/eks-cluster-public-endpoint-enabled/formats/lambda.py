"""
EKS Cluster Public Endpoint Enabled
Trigger: EventBridge rule matching CreateCluster or UpdateClusterConfig.
Use for: Real-time alerting on EKS control-plane exposure changes.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "eks.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in ("CreateCluster", "UpdateClusterConfig"):
        return {"matched": False}

    vpc = detail.get("requestParameters", {}).get("resourcesVpcConfig", {})
    cidrs = str(vpc.get("publicAccessCidrs", ""))
    if vpc.get("endpointPublicAccess") is not True and "0.0.0.0/0" not in cidrs:
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-025",
            "title": "EKS Cluster Public Endpoint Enabled",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "cluster_name": detail.get("requestParameters", {}).get("name"),
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
