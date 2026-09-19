"""
Lambda Event Source Mapping Created
Trigger: EventBridge rule matching CloudTrail CreateEventSourceMapping events.
Use for: Real-time enrichment of new source-to-function relationships.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "lambda.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "CreateEventSourceMapping":
        return {"matched": False}

    return {
        "matched": "requires-enrichment",
        "alert": {
            "rule_id": "det-013",
            "title": "Lambda Event Source Mapping Created",
            "severity": "Medium",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "function_name": detail.get("requestParameters", {}).get("functionName"),
            "event_source_arn": detail.get("requestParameters", {}).get("eventSourceArn"),
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime"),
        },
    }
