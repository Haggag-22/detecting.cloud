SELECT eventTime, userIdentity.arn, eventName, requestParameters.bucketName, requestParameters.key, requestParameters.acl, requestParameters.AccessControlPolicy, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND eventName IN ('PutBucketAcl', 'PutObjectAcl')
  AND (requestParameters.acl LIKE '%public%' OR requestParameters.acl LIKE '%authenticated%' OR requestParameters.AccessControlPolicy LIKE '%Grant%' OR requestParameters.AccessControlPolicy LIKE '%Grantee%')
ORDER BY eventTime DESC
