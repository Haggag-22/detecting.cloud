SELECT eventTime, userIdentity.arn, eventName, requestParameters.iamInstanceProfile, requestParameters.instancesSet, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ec2.amazonaws.com'
  AND eventName = 'RunInstances'
  AND requestParameters.iamInstanceProfile IS NOT NULL
ORDER BY eventTime DESC
