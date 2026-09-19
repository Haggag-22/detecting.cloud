SELECT eventTime, userIdentity.type, userIdentity.arn, eventName, requestParameters.volumeId, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ec2.amazonaws.com'
  AND eventName IN ('CreateSnapshot', 'CreateSnapshots')
ORDER BY eventTime DESC
