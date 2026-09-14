"""
DescribeConfigurationSettings Followed by Privileged Use
Trigger: EventBridge rule matching DescribeConfigurationSettings.
Use for: Correlation from Beanstalk configuration reads to later privileged cloud activity.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "elasticbeanstalk.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "DescribeConfigurationSettings":
        return {"matched": False}

    request = detail.get("requestParameters", {})
    return {
        "matched": "requires-beanstalk-recon-plus-privileged-use-correlation",
        "alert": {
            "rule_id": "det-125",
            "title": "DescribeConfigurationSettings Followed by Privileged Use",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "application_name": request.get("applicationName"),
            "environment_name": request.get("environmentName"),
            "event_time": detail.get("eventTime"),
        },
    }
