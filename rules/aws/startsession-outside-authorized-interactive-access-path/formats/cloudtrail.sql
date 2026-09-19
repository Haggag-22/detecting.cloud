SELECT eventTime, userIdentity.type, userIdentity.arn, userIdentity.principalId, userIdentity.sessionContext.sessionIssuer.arn, requestParameters.target, sourceIPAddress, userAgent
FROM cloudtrail_logs
WHERE eventSource = 'ssm.amazonaws.com'
  AND eventName = 'StartSession'
ORDER BY eventTime DESC
