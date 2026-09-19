SELECT eventTime, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.arn, eventName, requestParameters.instanceId, sourceIPAddress, userAgent
FROM cloudtrail_logs
WHERE eventSource = 'ec2-instance-connect.amazonaws.com'
  AND eventName = 'SendSerialConsoleSSHPublicKey'
ORDER BY eventTime DESC
