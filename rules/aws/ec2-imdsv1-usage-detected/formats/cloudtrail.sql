SELECT eventTime, userIdentity.type, userIdentity.arn, eventName, requestParameters.instanceId, requestParameters.metadataOptions.httpTokens, requestParameters.httpTokens, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ec2.amazonaws.com'
  AND (
    (eventName = 'RunInstances' AND requestParameters.metadataOptions.httpTokens = 'optional')
    OR (eventName = 'ModifyInstanceMetadataOptions' AND requestParameters.httpTokens = 'optional')
  )
ORDER BY eventTime DESC
