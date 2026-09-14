SELECT eventTime, userIdentity.type, userIdentity.arn, requestParameters.encrypted, responseElements.encrypted, responseElements.volumeId, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ec2.amazonaws.com'
  AND eventName = 'CreateVolume'
  AND (
    requestParameters.encrypted = false
    OR responseElements.encrypted = false
  )
ORDER BY eventTime DESC
