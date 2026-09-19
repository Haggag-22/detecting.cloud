SELECT eventTime, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.target, sourceIPAddress, userAgent
FROM cloudtrail_logs
WHERE eventSource = 'ssm.amazonaws.com'
  AND eventName = 'StartSession'
ORDER BY eventTime DESC
