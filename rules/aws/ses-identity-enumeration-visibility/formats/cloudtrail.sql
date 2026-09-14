SELECT eventTime, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.identityType, requestParameters.identities, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ses.amazonaws.com'
  AND eventName IN ('ListIdentities', 'GetIdentityVerificationAttributes')
ORDER BY eventTime DESC
