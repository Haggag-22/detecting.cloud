"""
Organizations SCP Modified or Detached
Trigger: EventBridge rule matching DetachPolicy, DeletePolicy, or UpdatePolicy.
Use for: Real-time alerting on organization guardrail weakening events.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "organizations.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") not in ("DetachPolicy", "DeletePolicy", "UpdatePolicy"):
        return {"matched": False}

    return {
        "matched": True,
        "alert": {
            "rule_id": "det-030",
            "title": "Organizations SCP Modified or Detached",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "event_name": detail.get("eventName"),
            "policy_id": detail.get("requestParameters", {}).get("policyId"),
            "target_id": detail.get("requestParameters", {}).get("targetId"),
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
