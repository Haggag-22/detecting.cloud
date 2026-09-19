SELECT eventTime, userIdentity.type, userIdentity.arn, eventName, requestParameters.bucketName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND (
    eventName = 'DeletePublicAccessBlock'
    OR (
      eventName = 'PutPublicAccessBlock'
      AND (
        requestParameters.PublicAccessBlockConfiguration.BlockPublicPolicy = false
        OR requestParameters.PublicAccessBlockConfiguration.RestrictPublicBuckets = false
        OR requestParameters.PublicAccessBlockConfiguration.BlockPublicAcls = false
        OR requestParameters.PublicAccessBlockConfiguration.IgnorePublicAcls = false
      )
    )
  )
ORDER BY eventTime DESC
