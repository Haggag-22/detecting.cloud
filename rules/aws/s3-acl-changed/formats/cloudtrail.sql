SELECT eventTime, userIdentity.arn, eventName, requestParameters.bucketName, requestParameters.key, requestParameters.acl, requestParameters.AccessControlPolicy, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND eventName IN ('PutBucketAcl', 'PutObjectAcl')
ORDER BY eventTime DESC
