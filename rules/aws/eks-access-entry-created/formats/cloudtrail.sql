SELECT eventTime, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.clusterName, requestParameters.principalArn, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'eks.amazonaws.com'
  AND eventName = 'CreateAccessEntry'
ORDER BY eventTime DESC
