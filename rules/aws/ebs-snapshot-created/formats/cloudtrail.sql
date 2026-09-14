SELECT eventTime, userIdentity.arn, eventName, requestParameters.volumeId, requestParameters.description, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ec2.amazonaws.com'
  AND eventName IN ('CreateSnapshot', 'CreateSnapshots')
ORDER BY eventTime DESC
