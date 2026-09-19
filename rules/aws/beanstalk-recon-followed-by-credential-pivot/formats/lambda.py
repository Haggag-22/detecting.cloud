"""
Beanstalk Recon Followed by Credential Pivot
Trigger: EventBridge rule matching DescribeConfigurationSettings.
Use for: Correlation from Beanstalk environment reconnaissance to later IAM or STS pivot activity.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "elasticbeanstalk.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "DescribeConfigurationSettings":
        return {"matched": False}

    return {
        "matched": "requires-beanstalk-recon-plus-pivot-correlation",
        "alert": {
            "rule_id": "det-119",
            "title": "Beanstalk Recon Followed by Credential Pivot",
            "severity": "Critical",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "application_name": detail.get("requestParameters", {}).get("applicationName"),
            "environment_name": detail.get("requestParameters", {}).get("environmentName"),
            "event_time": detail.get("eventTime"),
        },
    }
