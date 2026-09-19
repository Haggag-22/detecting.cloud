SELECT eventTime, userIdentity.arn, requestParameters.instanceId, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ec2-instance-connect.amazonaws.com'
  AND eventName = 'SendSSHPublicKey'
ORDER BY eventTime DESC
