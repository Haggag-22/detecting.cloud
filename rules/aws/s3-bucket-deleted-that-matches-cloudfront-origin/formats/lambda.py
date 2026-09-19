"""
S3 Bucket Deleted That Matches CloudFront Origin
Trigger: EventBridge rule matching DeleteBucket.
Use for: Real-time detection of CloudFront origin orphaning precursors.
"""

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if detail.get("eventSource") != "s3.amazonaws.com":
        return {"matched": False}
    if detail.get("eventName") != "DeleteBucket":
        return {"matched": False}

    return {
        "matched": "requires-cloudfront-origin-reference-check",
        "alert": {
            "rule_id": "det-136",
            "title": "S3 Bucket Deleted That Matches CloudFront Origin",
            "severity": "High",
            "actor": detail.get("userIdentity", {}).get("arn"),
            "bucket_name": detail.get("requestParameters", {}).get("bucketName"),
            "event_time": detail.get("eventTime"),
        },
    }
