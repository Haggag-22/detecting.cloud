"""
CloudTrail Logging Disabled
Trigger: EventBridge rule matching StopLogging, DeleteTrail, or UpdateTrail.
Use for: Real-time alerting when CloudTrail coverage or integrity is reduced.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "cloudtrail.amazonaws.com":
        return {"matched": False}
    if detail.get("errorCode"):
        return {"matched": False}

    name = detail.get("eventName")
    if name in ("StopLogging", "DeleteTrail"):
        return {"matched": True, "alert": {"rule_id": "det-002", "title": "CloudTrail Logging Disabled", "severity": "Critical", "actor": detail.get("userIdentity", {}).get("arn"), "trail_name": detail.get("requestParameters", {}).get("name"), "source_ip": detail.get("sourceIPAddress"), "event_time": detail.get("eventTime")}}

    request = detail.get("requestParameters", {})
    weakened = request.get("isMultiRegionTrail") is False or request.get("includeGlobalServiceEvents") is False or request.get("enableLogFileValidation") is False or request.get("isOrganizationTrail") is False
    if name == "UpdateTrail" and weakened:
        return {"matched": True, "alert": {"rule_id": "det-002", "title": "CloudTrail Logging Disabled", "severity": "Critical", "actor": detail.get("userIdentity", {}).get("arn"), "trail_name": request.get("name"), "source_ip": detail.get("sourceIPAddress"), "event_time": detail.get("eventTime")}}

    return {"matched": False}
