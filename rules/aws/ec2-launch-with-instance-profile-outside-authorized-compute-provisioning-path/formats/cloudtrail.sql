SELECT eventTime, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.iamInstanceProfile, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ec2.amazonaws.com'
  AND eventName = 'RunInstances'
  AND requestParameters.iamInstanceProfile IS NOT NULL
ORDER BY eventTime DESC
