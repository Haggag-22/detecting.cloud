SELECT eventTime, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.applicationName, requestParameters.environmentName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'elasticbeanstalk.amazonaws.com'
  AND eventName = 'DescribeConfigurationSettings'
ORDER BY eventTime DESC
