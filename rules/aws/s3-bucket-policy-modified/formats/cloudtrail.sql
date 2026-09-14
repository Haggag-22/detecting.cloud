SELECT eventTime, userIdentity.type, userIdentity.arn, eventName, requestParameters.bucketName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND eventName IN ('PutBucketPolicy', 'DeleteBucketPolicy')
ORDER BY eventTime DESC
