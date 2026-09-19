SELECT eventTime, userIdentity.type, userIdentity.arn, requestParameters.tableArn, requestParameters.s3Bucket, requestParameters.s3BucketOwner, requestParameters.s3Prefix, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'dynamodb.amazonaws.com'
  AND eventName = 'ExportTableToPointInTime'
ORDER BY eventTime DESC
