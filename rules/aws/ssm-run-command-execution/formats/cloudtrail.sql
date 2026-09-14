SELECT eventTime, userIdentity.type, userIdentity.arn, eventName, requestParameters.documentName, requestParameters.instanceIds, requestParameters.target, requestParameters.parameters, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ssm.amazonaws.com'
  AND eventName IN ('SendCommand', 'StartSession')
ORDER BY eventTime DESC
