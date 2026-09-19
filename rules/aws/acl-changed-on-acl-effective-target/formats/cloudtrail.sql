SELECT eventTime, userIdentity.arn, eventName, requestParameters.bucketName, requestParameters.key, requestParameters.acl, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND eventName IN ('PutBucketAcl', 'PutObjectAcl')
  AND (errorCode IS NULL OR errorCode = '')
ORDER BY eventTime DESC
