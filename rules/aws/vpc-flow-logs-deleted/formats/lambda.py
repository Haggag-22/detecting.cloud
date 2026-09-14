"""
VPC Flow Logs Deleted - Lambda/EventBridge Handler
Trigger: EventBridge rule matching CloudTrail DeleteFlowLogs events.
Use for: Real-time alerting, enrichment (DescribeFlowLogs, identity lookup), or integration with SOAR.
"""
import json
import boto3
from datetime import datetime

def lambda_handler(event, context):
    detail = event.get("detail", {})
    event_source = detail.get("eventSource", "")
    event_name = detail.get("eventName", "")

    # Detection logic: ec2.amazonaws.com + DeleteFlowLogs
    if event_source != "ec2.amazonaws.com" or event_name != "DeleteFlowLogs":
        return {"matched": False}

    user_identity = detail.get("userIdentity", {})
    flow_log_ids = detail.get("requestParameters", {}).get("flowLogIds", [])

    alert = {
        "rule_id": "det-110",
        "title": "VPC Flow Logs Deleted",
        "severity": "High",
        "timestamp": detail.get("eventTime", datetime.utcnow().isoformat() + "Z"),
        "actor": user_identity.get("arn", "unknown"),
        "source_ip": detail.get("sourceIPAddress", ""),
        "flow_log_ids": flow_log_ids,
        "account_id": detail.get("recipientAccountId", ""),
    }

    # Optional: Enrich with DescribeFlowLogs to get VPC/subnet context
    # ec2 = boto3.client("ec2")
    # for fl_id in flow_log_ids:
    #     resp = ec2.describe_flow_logs(FlowLogIds=[fl_id])
    #     ...

    return {"matched": True, "alert": alert}
