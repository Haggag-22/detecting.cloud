"""
DescribeConfigurationSettings Visibility
Trigger: EventBridge rule matching DescribeConfigurationSettings.
Use for: Baseline visibility into Elastic Beanstalk configuration reads.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "elasticbeanstalk.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "DescribeConfigurationSettings":
        return {"matched": False}

    request = detail.get("requestParameters", {})
    return {
        "matched": True,
        "alert": {
            "rule_id": "det-122",
            "title": "DescribeConfigurationSettings Visibility",
            "severity": "Medium",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "application_name": request.get("applicationName"),
            "environment_name": request.get("environmentName"),
            "event_time": detail.get("eventTime"),
        },
    }
