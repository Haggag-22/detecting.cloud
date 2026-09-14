"""
DescribeConfigurationSettings Outside Authorized Beanstalk Access Path
Trigger: EventBridge rule matching DescribeConfigurationSettings.
Use for: Authorization checks on Beanstalk configuration reads.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "elasticbeanstalk.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "DescribeConfigurationSettings":
        return {"matched": False}

    return {
        "matched": "requires-authorized-beanstalk-config-reader-check",
        "alert": {
            "rule_id": "det-123",
            "title": "DescribeConfigurationSettings Outside Authorized Beanstalk Access Path",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "event_time": detail.get("eventTime"),
        },
    }
