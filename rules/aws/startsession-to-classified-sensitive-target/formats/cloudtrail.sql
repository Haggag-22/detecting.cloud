SELECT eventTime, userIdentity.arn, requestParameters.target, sourceIPAddress
FROM cloudtrail_logs
WHERE eventSource = 'ssm.amazonaws.com'
  AND eventName = 'StartSession'
ORDER BY eventTime DESC
