SELECT eventTime, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.bucketName, requestParameters.key, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND eventName IN ('PutBucketAcl', 'PutObjectAcl')
ORDER BY eventTime DESC
