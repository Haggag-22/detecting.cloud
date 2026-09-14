SELECT eventTime, userIdentity.type, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ses.amazonaws.com'
  AND eventName IN ('ListIdentities', 'GetIdentityVerificationAttributes')
ORDER BY eventTime DESC
